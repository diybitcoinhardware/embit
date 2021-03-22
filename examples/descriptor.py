from embit.descriptor import Descriptor
from embit.networks import NETWORKS

# classic Bitcoin Core descriptors
classic_descriptors = [
    """
    wsh(sortedmulti(2,
        [775658e7/48h/1h/0h/1h]Upub5S3YzYL9wUjT9EVUpabdveZFQk9moQUuvXSb35vxbmFYAdEXd979eK27taPWaSmR9BH3nAkMbFWLFf4q3H59FA9zH8P6GQk7xSQuYVKSChj/0/*,
        [3193f8d3/48h/1h/0h/2h]tpubDEKfK8pLLATjieRRMSLPq34RdmRuNpXrBWCeiG7K1qgHrM6x1e821VdmxAXBheTYmVpoyNPni2bhzZ4qfFjcHpmGmyrkzbxWy2gZ6LcecDq/0/*,
        [9537bf0b/48h/1h/0h/2h]Vpub5m95PwsYnQp8krS98ygrRzxfacqdR3mCiFLnJbhtSTngm45EJg8UNSz9GGnoBc6dXMvievF3LSc2SakRn691Q9EwuDsVSafJNgf2CdzanzY/0/*
    ))
    """,
    "sh(wpkh([775658e7/49h/1h/0h]upub5Dhav3NrgESngrnJXvraLCn3TNTW4NYUk8sszdcxfyYfsMr9Uug1eLGW56369ofcGKCftCLGKnXGaPZRVvHiZnNAjECbWPuhP7N8Dba72z3/0/*))",
]
# paired descriptors with a set of allowed branches defined in a set: {a,b,c}. Usually {0,1} is used for receive & change descriptor pairs.
paired_descriptors = [
    """
    wsh(sortedmulti(2,
        [775658e7/48h/1h/0h/1h]Upub5S3YzYL9wUjT9EVUpabdveZFQk9moQUuvXSb35vxbmFYAdEXd979eK27taPWaSmR9BH3nAkMbFWLFf4q3H59FA9zH8P6GQk7xSQuYVKSChj/{0,1}/*,
        [3193f8d3/48h/1h/0h/2h]tpubDEKfK8pLLATjieRRMSLPq34RdmRuNpXrBWCeiG7K1qgHrM6x1e821VdmxAXBheTYmVpoyNPni2bhzZ4qfFjcHpmGmyrkzbxWy2gZ6LcecDq/{0,1}/*,
        [9537bf0b/48h/1h/0h/2h]Vpub5m95PwsYnQp8krS98ygrRzxfacqdR3mCiFLnJbhtSTngm45EJg8UNSz9GGnoBc6dXMvievF3LSc2SakRn691Q9EwuDsVSafJNgf2CdzanzY/{0,1}/*
    ))
    """,
    "wpkh([775658e7/84h/1h/0h]vpub5YomFkdenHbE1AbDaJV4kMfUh5UX4tt1Ed7B8mhSwyPxDw4wjim2qg4vd2vuYtYdsUUm9kmoCWLAbeABEY5HsMfeeN4okERNRUcmNXXgEBq/{33,45}/*)",
]
# miniscript descriptors
# Use http://bitcoin.sipa.be/miniscript/ to compile policy to miniscript
miniscript_descriptors = [
    """wsh(or_d(
        pk([775658e7/48h/1h/0h/1h]Upub5S3YzYL9wUjT9EVUpabdveZFQk9moQUuvXSb35vxbmFYAdEXd979eK27taPWaSmR9BH3nAkMbFWLFf4q3H59FA9zH8P6GQk7xSQuYVKSChj/{0,1}/*),
        and_v(
            v:pkh([9537bf0b/48h/1h/0h/2h]Vpub5m95PwsYnQp8krS98ygrRzxfacqdR3mCiFLnJbhtSTngm45EJg8UNSz9GGnoBc6dXMvievF3LSc2SakRn691Q9EwuDsVSafJNgf2CdzanzY/{0,1}/*),
            older(14400)))
        )
    """
]

def main():
    for dstr in classic_descriptors:
        # replace spaces and new lines
        dstr = dstr.replace("\n","").replace(" ","")
        # parse
        desc = Descriptor.from_string(dstr)
        # print(desc.policy)
        derived = desc.derive(12)
        print("Derived descriptor:\n%s" % derived)
        addr = derived.address(NETWORKS['test'])
        print("Address: %s\n" % addr)

    for dstr in paired_descriptors:
        # replace spaces and new lines
        dstr = dstr.replace("\n","").replace(" ","")
        # parse
        desc = Descriptor.from_string(dstr)
        # print(desc.policy)
        # 12-th address, testnet, 1st branch (change)
        # branch_index is the index of the allowed set, so if the set is {33,45} then branch_index=1 will derive using 45 index
        derived = desc.derive(12, branch_index=1)
        print("Derived descriptor:\n%s" % derived)
        addr = derived.address(NETWORKS['test'])
        print("Address: %s\n" % addr)

    for dstr in miniscript_descriptors:
        # replace spaces and new lines
        dstr = dstr.replace("\n","").replace(" ","")
        # parse
        desc = Descriptor.from_string(dstr)
        # print(desc.policy)
        # 12-th address, testnet, 1st branch (change)
        # if branch_index is not provided, we use the first index in all branches 
        derived = desc.derive(12)
        print("Derived descriptor:\n%s" % derived)
        addr = derived.address(NETWORKS['test'])
        print("Address: %s\n" % addr)

if __name__ == '__main__':
    main()