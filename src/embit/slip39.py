import hmac
import random
import sys

if sys.implementation.name == "micropython":
    import hashlib
    from micropython import const
else:
    from .util import hashlib, const


from .bip39 import mnemonic_from_bytes, mnemonic_to_bytes


# functions for SLIP39 checksum
def rs1024_polymod(values):
    GEN = [
        0xE0E040,
        0x1C1C080,
        0x3838100,
        0x7070200,
        0xE0E0009,
        0x1C0C2412,
        0x38086C24,
        0x3090FC48,
        0x21B1F890,
        0x3F3F120,
    ]
    chk = 1
    for v in values:
        b = chk >> 20
        chk = (chk & 0xFFFFF) << 10 ^ v
        for i in range(10):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def rs1024_verify_checksum(cs, data):
    return rs1024_polymod([x for x in cs] + data) == 1


def rs1024_create_checksum(cs, data):
    values = [x for x in cs] + data
    polymod = rs1024_polymod(values + [0, 0, 0]) ^ 1
    return [(polymod >> 10 * (2 - i)) & 1023 for i in range(3)]


# function for encryption/decryption
def _crypt(payload, id, exponent, passphrase, indices):
    if len(payload) % 2:
        raise ValueError("payload should be an even number of bytes")
    else:
        half = len(payload) // 2
    left = payload[:half]
    right = payload[half:]
    salt = b"shamir" + id.to_bytes(2, "big")
    for i in indices:
        f = hashlib.pbkdf2_hmac_sha256(
            i + passphrase,
            salt + right,
            2500 << exponent,
            half,
        )
        left, right = right, bytes(x ^ y for x, y in zip(left, f))
    return right + left


class Share:
    def __init__(
        self,
        share_bit_length,
        id,
        exponent,
        group_index,
        group_threshold,
        group_count,
        member_index,
        member_threshold,
        value,
    ):
        self.share_bit_length = share_bit_length
        self.id = id
        self.exponent = exponent
        self.group_index = group_index
        if group_index < 0 or group_index > 15:
            raise ValueError(
                "Group index should be between 0 and 15 inclusive"
            )
        self.group_threshold = group_threshold
        if group_threshold < 1 or group_threshold > group_count:
            raise ValueError(
                "Group threshold should be between 1 and %d inclusive" % group_count
            )
        self.group_count = group_count
        if group_count < 1 or group_count > 16:
            raise ValueError(
                "Group count should be between 1 and 16 inclusive"
            )
        self.member_index = member_index
        if member_index < 0 or member_index > 15:
            raise ValueError(
                "Member index should be between 0 and 15 inclusive"
            )
        self.member_threshold = member_threshold
        if member_threshold < 1 or member_threshold > 16:
            raise ValueError(
                "Member threshold should be between 1 and 16 inclusive"
            )
        self.value = value
        self.bytes = value.to_bytes(share_bit_length // 8, "big")

    @classmethod
    def parse(cls, mnemonic):
        # convert mnemonic into bits
        words = mnemonic.split()
        indices = [SLIP39_WORDS.index(word) for word in words]
        if not rs1024_verify_checksum(b"shamir", indices):
            raise ValueError("Invalid Checksum")
        id = (indices[0] << 5) | (indices[1] >> 5)
        exponent = indices[1] & 31
        group_index = indices[2] >> 6
        group_threshold = ((indices[2] >> 2) & 15) + 1
        group_count = (((indices[2] & 3) << 2) | (indices[3] >> 8)) + 1
        member_index = (indices[3] >> 4) & 15
        member_threshold = (indices[3] & 15) + 1
        value = 0
        for index in indices[4:-3]:
            value = (value << 10) | index
        share_bit_length = (len(indices) - 7) * 10 // 16 * 16
        if value >> share_bit_length != 0:
            raise SyntaxError("Share not 0-padded properly")
        if share_bit_length < 128:
            raise ValueError("not enough bits")
        return cls(
            share_bit_length,
            id,
            exponent,
            group_index,
            group_threshold,
            group_count,
            member_index,
            member_threshold,
            value,
        )

    def mnemonic(self):
        all_bits = (self.id << 5) | self.exponent
        all_bits <<= 4
        all_bits |= self.group_index
        all_bits <<= 4
        all_bits |= self.group_threshold - 1
        all_bits <<= 4
        all_bits |= self.group_count - 1
        all_bits <<= 4
        all_bits |= self.member_index
        all_bits <<= 4
        all_bits |= self.member_threshold - 1
        padding = 10 - self.share_bit_length % 10
        all_bits <<= padding + self.share_bit_length
        all_bits |= self.value
        num_words = 4 + (padding + self.share_bit_length) // 10
        indices = [
            (all_bits >> 10 * (num_words - i - 1)) & 1023 for i in range(num_words)
        ]
        checksum = rs1024_create_checksum(b"shamir", indices)
        return " ".join([SLIP39_WORDS[index] for index in indices + checksum])


class ShareSet:
    @classmethod
    def _load(cls):
        """Pre-computes the exponent/log for LaGrange calculation"""
        cls.exp = [0] * 255
        cls.log2 = [0] * 256
        cur = 1
        for i in range(255):
            cls.exp[i] = cur
            cls.log2[cur] = i
            cur = (cur << 1) ^ cur
            if cur > 255:
                cur ^= 0x11B

    def __init__(self, shares):
        self.shares = shares
        if len(shares) > 1:
            # check that the identifiers are the same
            ids = {s.id for s in shares}
            if len(ids) != 1:
                raise TypeError("Shares are from different secrets")
            # check that the exponents are the same
            exponents = {s.exponent for s in shares}
            if len(exponents) != 1:
                raise TypeError("Shares should have the same exponent")
            # check that the k-of-n is the same
            k = {s.group_threshold for s in shares}
            if len(k) != 1:
                raise ValueError("K of K-of-N should be the same")
            n = {s.group_count for s in shares}
            if len(n) != 1:
                raise ValueError("N of K-of-N should be the same")
            if k.pop() > n.pop():
                raise ValueError("K > N in K-of-N")
            # check that the share lengths are the same
            lengths = {s.share_bit_length for s in shares}
            if len(lengths) != 1:
                raise ValueError("all shares should have the same length")
            # check that the x coordinates are unique
            xs = {(s.group_index, s.member_index) for s in shares}
            if len(xs) != len(shares):
                raise ValueError("Share indices should be unique")
        self.id = shares[0].id
        self.salt = b"shamir" + self.id.to_bytes(2, "big")
        self.exponent = shares[0].exponent
        self.group_threshold = shares[0].group_threshold
        self.group_count = shares[0].group_count
        self.share_bit_length = shares[0].share_bit_length

    def decrypt(self, secret, passphrase=b""):
        # decryption does the reverse of encryption
        indices = (b"\x03", b"\x02", b"\x01", b"\x00")
        return _crypt(secret, self.id, self.exponent, passphrase, indices)

    @classmethod
    def encrypt(cls, payload, id, exponent, passphrase=b""):
        # encryption goes from 0 to 3 in bytes
        indices = (b"\x00", b"\x01", b"\x02", b"\x03")
        return _crypt(payload, id, exponent, passphrase, indices)

    @classmethod
    def interpolate(cls, x, share_data):
        """Gets the y value at a particular x"""
        # we're using the LaGrange formula
        # https://github.com/satoshilabs/slips/blob/master/slip-0039/lagrange.png
        # the numerator of the multiplication part is what we're pre-computing
        # (x - x_i) 0<=i<=m where x_i is each x in the share
        # we don't store this, but the log of this
        # and exponentiate later
        log_product = sum(cls.log2[share_x ^ x] for share_x, _ in share_data)
        # the y value that we want is stored in result
        result = bytes(len(share_data[0][1]))
        for share_x, share_bytes in share_data:
            # we have to subtract the current x - x_i since
            # the formula is for j where j != i
            log_numerator = log_product - cls.log2[share_x ^ x]
            # the denominator we can just sum because we cheated and made
            # log(0) = 0 which will happen when i = j
            log_denominator = sum(
                cls.log2[share_x ^ other_x] for other_x, _ in share_data
            )
            log = (log_numerator - log_denominator) % 255
            result = bytes(
                c ^ (cls.exp[(cls.log2[y] + log) % 255] if y > 0 else 0)
                for y, c in zip(share_bytes, result)
            )
        return result

    @classmethod
    def digest(cls, r, shared_secret):
        return hmac.new(r, shared_secret, "sha256").digest()[:4]

    @classmethod
    def recover_secret(cls, share_data):
        """return a shared secret from a list of shares"""
        shared_secret = cls.interpolate(255, share_data)
        digest_share = cls.interpolate(254, share_data)
        digest = digest_share[:4]
        random = digest_share[4:]
        if digest != cls.digest(random, shared_secret):
            raise ValueError("Digest does not match secret")
        return shared_secret

    def recover(self, passphrase=b""):
        """recover a shared secret from the current group of shares"""
        # group by group index
        groups = [[] for _ in range(self.group_count)]
        for share in self.shares:
            groups[share.group_index].append(share)
        # gather share data of each group
        share_data = []
        for i, group in enumerate(groups):
            if len(group) == 0:
                continue
            member_thresholds = {share.member_threshold for share in group}
            if len(member_thresholds) != 1:
                raise ValueError("Member thresholds should be the same within a group")
            member_threshold = member_thresholds.pop()
            if member_threshold == 1:
                share_data.append((i, group[0].bytes))
            elif member_threshold > len(group):
                raise ValueError("Not enough shares")
            else:
                member_data = [(share.member_index, share.bytes) for share in group]
                share_data.append((i, self.recover_secret(member_data)))
        if self.group_threshold == 1:
            return self.decrypt(share_data[0][1], passphrase)
        elif self.group_threshold > len(share_data):
            raise ValueError("Not enough shares")
        shared_secret = self.recover_secret(share_data)
        return self.decrypt(shared_secret, passphrase)

    @classmethod
    def split_secret(cls, secret, k, n, randint=random.randint):
        """Split secret into k-of-n shares"""
        if n < 1:
            raise ValueError("N is too small, must be at least 1")
        if n > 16:
            raise ValueError("N is too big, must be 16 or less")
        if k < 1:
            raise ValueError("K is too small, must be at least 1")
        if k > n:
            raise ValueError("K is too big, K <= N")
        num_bytes = len(secret)
        if num_bytes not in (16, 32):
            raise ValueError("secret should be 128 bits or 256 bits")
        if k == 1:
            return [(0, secret)]
        else:
            r = bytes(randint(0, 255) for _ in range(num_bytes - 4))
            digest = cls.digest(r, secret)
            digest_share = digest + r
            share_data = [
                (i, bytes(randint(0, 255) for _ in range(num_bytes))) for i in range(k - 2)
            ]
            more_data = share_data.copy()
            share_data.append((254, digest_share))
            share_data.append((255, secret))
            for i in range(k - 2, n):
                more_data.append((i, cls.interpolate(i, share_data)))
        return more_data

    @classmethod
    def generate_shares(cls, mnemonic, k, n, passphrase=b"", exponent=0, randint=random.randint):
        """Takes a BIP39 mnemonic along with k, n, passphrase and exponent.
        Returns a list of SLIP39 mnemonics, any k of of which, along with the passphrase, recover the secret"""
        # convert mnemonic to a shared secret
        secret = mnemonic_to_bytes(mnemonic)
        num_bits = len(secret) * 8
        if num_bits not in (128, 256):
            raise ValueError("mnemonic must be 12 or 24 words")
        # generate id
        id = randint(0, 32767)
        # encrypt secret with passphrase
        encrypted = cls.encrypt(secret, id, exponent, passphrase)
        # split encrypted payload and create shares
        shares = []
        data = cls.split_secret(encrypted, k, n)
        for group_index, share_bytes in data:
            share = Share(
                share_bit_length=num_bits,
                id=id,
                exponent=exponent,
                group_index=group_index,
                group_threshold=k,
                group_count=n,
                member_index=0,
                member_threshold=1,
                value=int.from_bytes(share_bytes, "big"),
            )
            shares.append(share.mnemonic())
        return shares

    @classmethod
    def recover_mnemonic(cls, share_mnemonics, passphrase=b""):
        """Recovers the BIP39 mnemonic from a bunch of SLIP39 mnemonics"""
        shares = [Share.parse(m) for m in share_mnemonics]
        share_set = ShareSet(shares)
        secret = share_set.recover(passphrase)
        return mnemonic_from_bytes(secret)


ShareSet._load()


SLIP39_WORDS = [
    "academic",
    "acid",
    "acne",
    "acquire",
    "acrobat",
    "activity",
    "actress",
    "adapt",
    "adequate",
    "adjust",
    "admit",
    "adorn",
    "adult",
    "advance",
    "advocate",
    "afraid",
    "again",
    "agency",
    "agree",
    "aide",
    "aircraft",
    "airline",
    "airport",
    "ajar",
    "alarm",
    "album",
    "alcohol",
    "alien",
    "alive",
    "alpha",
    "already",
    "alto",
    "aluminum",
    "always",
    "amazing",
    "ambition",
    "amount",
    "amuse",
    "analysis",
    "anatomy",
    "ancestor",
    "ancient",
    "angel",
    "angry",
    "animal",
    "answer",
    "antenna",
    "anxiety",
    "apart",
    "aquatic",
    "arcade",
    "arena",
    "argue",
    "armed",
    "artist",
    "artwork",
    "aspect",
    "auction",
    "august",
    "aunt",
    "average",
    "aviation",
    "avoid",
    "award",
    "away",
    "axis",
    "axle",
    "beam",
    "beard",
    "beaver",
    "become",
    "bedroom",
    "behavior",
    "being",
    "believe",
    "belong",
    "benefit",
    "best",
    "beyond",
    "bike",
    "biology",
    "birthday",
    "bishop",
    "black",
    "blanket",
    "blessing",
    "blimp",
    "blind",
    "blue",
    "body",
    "bolt",
    "boring",
    "born",
    "both",
    "boundary",
    "bracelet",
    "branch",
    "brave",
    "breathe",
    "briefing",
    "broken",
    "brother",
    "browser",
    "bucket",
    "budget",
    "building",
    "bulb",
    "bulge",
    "bumpy",
    "bundle",
    "burden",
    "burning",
    "busy",
    "buyer",
    "cage",
    "calcium",
    "camera",
    "campus",
    "canyon",
    "capacity",
    "capital",
    "capture",
    "carbon",
    "cards",
    "careful",
    "cargo",
    "carpet",
    "carve",
    "category",
    "cause",
    "ceiling",
    "center",
    "ceramic",
    "champion",
    "change",
    "charity",
    "check",
    "chemical",
    "chest",
    "chew",
    "chubby",
    "cinema",
    "civil",
    "class",
    "clay",
    "cleanup",
    "client",
    "climate",
    "clinic",
    "clock",
    "clogs",
    "closet",
    "clothes",
    "club",
    "cluster",
    "coal",
    "coastal",
    "coding",
    "column",
    "company",
    "corner",
    "costume",
    "counter",
    "course",
    "cover",
    "cowboy",
    "cradle",
    "craft",
    "crazy",
    "credit",
    "cricket",
    "criminal",
    "crisis",
    "critical",
    "crowd",
    "crucial",
    "crunch",
    "crush",
    "crystal",
    "cubic",
    "cultural",
    "curious",
    "curly",
    "custody",
    "cylinder",
    "daisy",
    "damage",
    "dance",
    "darkness",
    "database",
    "daughter",
    "deadline",
    "deal",
    "debris",
    "debut",
    "decent",
    "decision",
    "declare",
    "decorate",
    "decrease",
    "deliver",
    "demand",
    "density",
    "deny",
    "depart",
    "depend",
    "depict",
    "deploy",
    "describe",
    "desert",
    "desire",
    "desktop",
    "destroy",
    "detailed",
    "detect",
    "device",
    "devote",
    "diagnose",
    "dictate",
    "diet",
    "dilemma",
    "diminish",
    "dining",
    "diploma",
    "disaster",
    "discuss",
    "disease",
    "dish",
    "dismiss",
    "display",
    "distance",
    "dive",
    "divorce",
    "document",
    "domain",
    "domestic",
    "dominant",
    "dough",
    "downtown",
    "dragon",
    "dramatic",
    "dream",
    "dress",
    "drift",
    "drink",
    "drove",
    "drug",
    "dryer",
    "duckling",
    "duke",
    "duration",
    "dwarf",
    "dynamic",
    "early",
    "earth",
    "easel",
    "easy",
    "echo",
    "eclipse",
    "ecology",
    "edge",
    "editor",
    "educate",
    "either",
    "elbow",
    "elder",
    "election",
    "elegant",
    "element",
    "elephant",
    "elevator",
    "elite",
    "else",
    "email",
    "emerald",
    "emission",
    "emperor",
    "emphasis",
    "employer",
    "empty",
    "ending",
    "endless",
    "endorse",
    "enemy",
    "energy",
    "enforce",
    "engage",
    "enjoy",
    "enlarge",
    "entrance",
    "envelope",
    "envy",
    "epidemic",
    "episode",
    "equation",
    "equip",
    "eraser",
    "erode",
    "escape",
    "estate",
    "estimate",
    "evaluate",
    "evening",
    "evidence",
    "evil",
    "evoke",
    "exact",
    "example",
    "exceed",
    "exchange",
    "exclude",
    "excuse",
    "execute",
    "exercise",
    "exhaust",
    "exotic",
    "expand",
    "expect",
    "explain",
    "express",
    "extend",
    "extra",
    "eyebrow",
    "facility",
    "fact",
    "failure",
    "faint",
    "fake",
    "false",
    "family",
    "famous",
    "fancy",
    "fangs",
    "fantasy",
    "fatal",
    "fatigue",
    "favorite",
    "fawn",
    "fiber",
    "fiction",
    "filter",
    "finance",
    "findings",
    "finger",
    "firefly",
    "firm",
    "fiscal",
    "fishing",
    "fitness",
    "flame",
    "flash",
    "flavor",
    "flea",
    "flexible",
    "flip",
    "float",
    "floral",
    "fluff",
    "focus",
    "forbid",
    "force",
    "forecast",
    "forget",
    "formal",
    "fortune",
    "forward",
    "founder",
    "fraction",
    "fragment",
    "frequent",
    "freshman",
    "friar",
    "fridge",
    "friendly",
    "frost",
    "froth",
    "frozen",
    "fumes",
    "funding",
    "furl",
    "fused",
    "galaxy",
    "game",
    "garbage",
    "garden",
    "garlic",
    "gasoline",
    "gather",
    "general",
    "genius",
    "genre",
    "genuine",
    "geology",
    "gesture",
    "glad",
    "glance",
    "glasses",
    "glen",
    "glimpse",
    "goat",
    "golden",
    "graduate",
    "grant",
    "grasp",
    "gravity",
    "gray",
    "greatest",
    "grief",
    "grill",
    "grin",
    "grocery",
    "gross",
    "group",
    "grownup",
    "grumpy",
    "guard",
    "guest",
    "guilt",
    "guitar",
    "gums",
    "hairy",
    "hamster",
    "hand",
    "hanger",
    "harvest",
    "have",
    "havoc",
    "hawk",
    "hazard",
    "headset",
    "health",
    "hearing",
    "heat",
    "helpful",
    "herald",
    "herd",
    "hesitate",
    "hobo",
    "holiday",
    "holy",
    "home",
    "hormone",
    "hospital",
    "hour",
    "huge",
    "human",
    "humidity",
    "hunting",
    "husband",
    "hush",
    "husky",
    "hybrid",
    "idea",
    "identify",
    "idle",
    "image",
    "impact",
    "imply",
    "improve",
    "impulse",
    "include",
    "income",
    "increase",
    "index",
    "indicate",
    "industry",
    "infant",
    "inform",
    "inherit",
    "injury",
    "inmate",
    "insect",
    "inside",
    "install",
    "intend",
    "intimate",
    "invasion",
    "involve",
    "iris",
    "island",
    "isolate",
    "item",
    "ivory",
    "jacket",
    "jerky",
    "jewelry",
    "join",
    "judicial",
    "juice",
    "jump",
    "junction",
    "junior",
    "junk",
    "jury",
    "justice",
    "kernel",
    "keyboard",
    "kidney",
    "kind",
    "kitchen",
    "knife",
    "knit",
    "laden",
    "ladle",
    "ladybug",
    "lair",
    "lamp",
    "language",
    "large",
    "laser",
    "laundry",
    "lawsuit",
    "leader",
    "leaf",
    "learn",
    "leaves",
    "lecture",
    "legal",
    "legend",
    "legs",
    "lend",
    "length",
    "level",
    "liberty",
    "library",
    "license",
    "lift",
    "likely",
    "lilac",
    "lily",
    "lips",
    "liquid",
    "listen",
    "literary",
    "living",
    "lizard",
    "loan",
    "lobe",
    "location",
    "losing",
    "loud",
    "loyalty",
    "luck",
    "lunar",
    "lunch",
    "lungs",
    "luxury",
    "lying",
    "lyrics",
    "machine",
    "magazine",
    "maiden",
    "mailman",
    "main",
    "makeup",
    "making",
    "mama",
    "manager",
    "mandate",
    "mansion",
    "manual",
    "marathon",
    "march",
    "market",
    "marvel",
    "mason",
    "material",
    "math",
    "maximum",
    "mayor",
    "meaning",
    "medal",
    "medical",
    "member",
    "memory",
    "mental",
    "merchant",
    "merit",
    "method",
    "metric",
    "midst",
    "mild",
    "military",
    "mineral",
    "minister",
    "miracle",
    "mixed",
    "mixture",
    "mobile",
    "modern",
    "modify",
    "moisture",
    "moment",
    "morning",
    "mortgage",
    "mother",
    "mountain",
    "mouse",
    "move",
    "much",
    "mule",
    "multiple",
    "muscle",
    "museum",
    "music",
    "mustang",
    "nail",
    "national",
    "necklace",
    "negative",
    "nervous",
    "network",
    "news",
    "nuclear",
    "numb",
    "numerous",
    "nylon",
    "oasis",
    "obesity",
    "object",
    "observe",
    "obtain",
    "ocean",
    "often",
    "olympic",
    "omit",
    "oral",
    "orange",
    "orbit",
    "order",
    "ordinary",
    "organize",
    "ounce",
    "oven",
    "overall",
    "owner",
    "paces",
    "pacific",
    "package",
    "paid",
    "painting",
    "pajamas",
    "pancake",
    "pants",
    "papa",
    "paper",
    "parcel",
    "parking",
    "party",
    "patent",
    "patrol",
    "payment",
    "payroll",
    "peaceful",
    "peanut",
    "peasant",
    "pecan",
    "penalty",
    "pencil",
    "percent",
    "perfect",
    "permit",
    "petition",
    "phantom",
    "pharmacy",
    "photo",
    "phrase",
    "physics",
    "pickup",
    "picture",
    "piece",
    "pile",
    "pink",
    "pipeline",
    "pistol",
    "pitch",
    "plains",
    "plan",
    "plastic",
    "platform",
    "playoff",
    "pleasure",
    "plot",
    "plunge",
    "practice",
    "prayer",
    "preach",
    "predator",
    "pregnant",
    "premium",
    "prepare",
    "presence",
    "prevent",
    "priest",
    "primary",
    "priority",
    "prisoner",
    "privacy",
    "prize",
    "problem",
    "process",
    "profile",
    "program",
    "promise",
    "prospect",
    "provide",
    "prune",
    "public",
    "pulse",
    "pumps",
    "punish",
    "puny",
    "pupal",
    "purchase",
    "purple",
    "python",
    "quantity",
    "quarter",
    "quick",
    "quiet",
    "race",
    "racism",
    "radar",
    "railroad",
    "rainbow",
    "raisin",
    "random",
    "ranked",
    "rapids",
    "raspy",
    "reaction",
    "realize",
    "rebound",
    "rebuild",
    "recall",
    "receiver",
    "recover",
    "regret",
    "regular",
    "reject",
    "relate",
    "remember",
    "remind",
    "remove",
    "render",
    "repair",
    "repeat",
    "replace",
    "require",
    "rescue",
    "research",
    "resident",
    "response",
    "result",
    "retailer",
    "retreat",
    "reunion",
    "revenue",
    "review",
    "reward",
    "rhyme",
    "rhythm",
    "rich",
    "rival",
    "river",
    "robin",
    "rocky",
    "romantic",
    "romp",
    "roster",
    "round",
    "royal",
    "ruin",
    "ruler",
    "rumor",
    "sack",
    "safari",
    "salary",
    "salon",
    "salt",
    "satisfy",
    "satoshi",
    "saver",
    "says",
    "scandal",
    "scared",
    "scatter",
    "scene",
    "scholar",
    "science",
    "scout",
    "scramble",
    "screw",
    "script",
    "scroll",
    "seafood",
    "season",
    "secret",
    "security",
    "segment",
    "senior",
    "shadow",
    "shaft",
    "shame",
    "shaped",
    "sharp",
    "shelter",
    "sheriff",
    "short",
    "should",
    "shrimp",
    "sidewalk",
    "silent",
    "silver",
    "similar",
    "simple",
    "single",
    "sister",
    "skin",
    "skunk",
    "slap",
    "slavery",
    "sled",
    "slice",
    "slim",
    "slow",
    "slush",
    "smart",
    "smear",
    "smell",
    "smirk",
    "smith",
    "smoking",
    "smug",
    "snake",
    "snapshot",
    "sniff",
    "society",
    "software",
    "soldier",
    "solution",
    "soul",
    "source",
    "space",
    "spark",
    "speak",
    "species",
    "spelling",
    "spend",
    "spew",
    "spider",
    "spill",
    "spine",
    "spirit",
    "spit",
    "spray",
    "sprinkle",
    "square",
    "squeeze",
    "stadium",
    "staff",
    "standard",
    "starting",
    "station",
    "stay",
    "steady",
    "step",
    "stick",
    "stilt",
    "story",
    "strategy",
    "strike",
    "style",
    "subject",
    "submit",
    "sugar",
    "suitable",
    "sunlight",
    "superior",
    "surface",
    "surprise",
    "survive",
    "sweater",
    "swimming",
    "swing",
    "switch",
    "symbolic",
    "sympathy",
    "syndrome",
    "system",
    "tackle",
    "tactics",
    "tadpole",
    "talent",
    "task",
    "taste",
    "taught",
    "taxi",
    "teacher",
    "teammate",
    "teaspoon",
    "temple",
    "tenant",
    "tendency",
    "tension",
    "terminal",
    "testify",
    "texture",
    "thank",
    "that",
    "theater",
    "theory",
    "therapy",
    "thorn",
    "threaten",
    "thumb",
    "thunder",
    "ticket",
    "tidy",
    "timber",
    "timely",
    "ting",
    "tofu",
    "together",
    "tolerate",
    "total",
    "toxic",
    "tracks",
    "traffic",
    "training",
    "transfer",
    "trash",
    "traveler",
    "treat",
    "trend",
    "trial",
    "tricycle",
    "trip",
    "triumph",
    "trouble",
    "true",
    "trust",
    "twice",
    "twin",
    "type",
    "typical",
    "ugly",
    "ultimate",
    "umbrella",
    "uncover",
    "undergo",
    "unfair",
    "unfold",
    "unhappy",
    "union",
    "universe",
    "unkind",
    "unknown",
    "unusual",
    "unwrap",
    "upgrade",
    "upstairs",
    "username",
    "usher",
    "usual",
    "valid",
    "valuable",
    "vampire",
    "vanish",
    "various",
    "vegan",
    "velvet",
    "venture",
    "verdict",
    "verify",
    "very",
    "veteran",
    "vexed",
    "victim",
    "video",
    "view",
    "vintage",
    "violence",
    "viral",
    "visitor",
    "visual",
    "vitamins",
    "vocal",
    "voice",
    "volume",
    "voter",
    "voting",
    "walnut",
    "warmth",
    "warn",
    "watch",
    "wavy",
    "wealthy",
    "weapon",
    "webcam",
    "welcome",
    "welfare",
    "western",
    "width",
    "wildlife",
    "window",
    "wine",
    "wireless",
    "wisdom",
    "withdraw",
    "wits",
    "wolf",
    "woman",
    "work",
    "worthy",
    "wrap",
    "wrist",
    "writing",
    "wrote",
    "year",
    "yelp",
    "yield",
    "yoga",
    "zero",
]
