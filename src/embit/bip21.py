"""BIP21 Bitcoin URI handling"""

import re
from urllib.parse import quote, unquote, urlparse, parse_qs
from decimal import Decimal, InvalidOperation, ROUND_FLOOR
from .base import EmbitBase, EmbitError


class BIP21Error(EmbitError):
    """BIP21 URI parsing/validation error"""
    pass


class BitcoinURI(EmbitBase):
    """
    Bitcoin URI handler implementing BIP-21/BIP-321. 
    Used by BIP-353 implementation to extract payment information from a human-readable name.
    
    Supports:
    - Standard bitcoin: URIs
    - URL encoding/decoding
    - Required field validation (req- prefix)
    - Standard fields: amount, label, message
    - Silent payments addresses (sp parameter)
    - Bech32(m) addresses (bc parameter)
    """
    
    # Standard field names
    FIELD_MESSAGE = "message"
    FIELD_LABEL = "label"
    FIELD_AMOUNT = "amount"
    FIELD_BC = "bc"  # Bech32(m) address parameter
    FIELD_SILENT_PAYMENT = "sp"
    FIELD_POP = "pop"
    
    # Fields that MUST NOT have duplicates
    NO_DUPLICATE_FIELDS = {FIELD_LABEL, FIELD_MESSAGE, FIELD_AMOUNT, FIELD_POP}
    
    # Fields that are payment instructions and MAY have duplicates
    PAYMENT_INSTRUCTION_FIELDS = {FIELD_BC, FIELD_SILENT_PAYMENT}
    
    # Constants
    BITCOIN_SCHEME = "bitcoin"
    MAX_BITCOIN = 21000000
    SATOSHIS_PER_BITCOIN = 100000000
    SMALLEST_UNIT_EXPONENT = 8
      
    # Bech32/Bech32m addresses: max 90 characters total (from BIP173)
    # Minimum: HRP (2 chars) + "1" + 6 chars checksum + data (min 2 chars) = 11 chars
    # Base58 addresses (P2PKH/P2SH): typically 26-35 characters. We take bech32 as reference.
    MIN_BECH32_LENGTH = 11
    MAX_BECH32_LENGTH = 90
    
    def __init__(self, uri_string: str):
        """
        Parse a Bitcoin URI string.
        
        Args:
            uri_string: The URI string to parse
            
        Raises:
            BIP21Error: If the URI is invalid
        """
        self.uri_string = uri_string
        self.parameters = {}
        
        # Parse the URI
        try:
            parsed = urlparse(uri_string)
        except Exception as e:
            raise BIP21Error(f"Bad URI syntax: {e}")
        
        # Validate scheme
        if parsed.scheme.lower() != self.BITCOIN_SCHEME:
            raise BIP21Error(f"Unsupported URI scheme: {parsed.scheme}")
        
        # Extract address and parameters
        path = parsed.path
        
        # Split address from query params
        if "?" in uri_string:
            address_part = path
            query_part = parsed.query
        else:
            address_part = path
            query_part = ""
        
        # Parse address if present
        if address_part:
            try:
                # Basic address length validation. We rely on the coordinator to validate the address before.
                if len(address_part) < self.MIN_BECH32_LENGTH or len(address_part) > self.MAX_BECH32_LENGTH:
                    raise ValueError("Invalid address length")
                self._put_with_validation("uri_address", address_part)
            except Exception as e:
                raise BIP21Error(f"Invalid address: {e}")
        
        # Initialize payment instruction fields as lists
        for field in self.PAYMENT_INSTRUCTION_FIELDS:
            self.parameters[field] = []
        
        # Parse query parameters
        if query_part:
            params = parse_qs(query_part, keep_blank_values=True)
            for name, values in params.items():
                name_lower = name.lower()

                # Check for forbidden duplicates
                if name_lower in self.NO_DUPLICATE_FIELDS and len(values) > 1:
                    raise BIP21Error(f"Multiple query parameters with key '{name}' are not allowed")
                
                # Handle payment instruction fields that can have multiple values
                if name_lower in self.PAYMENT_INSTRUCTION_FIELDS:
                    for value in values:
                        if value:
                            self._parse_parameter(name_lower, value)
                else:
                    # For other fields, take the first value only
                    value = values[0] if values else ""
                    self._parse_parameter(name_lower, value)
        
    def _parse_parameter(self, name: str, value: str):
        """Parse a single parameter name/value pair"""
        if name == self.FIELD_AMOUNT and value:
            try:
                # Parse amount as decimal with up to 8 decimal places
                amount_decimal = Decimal(value.replace(',', '.'))
                
                if amount_decimal < 0:
                    raise ValueError("Negative amount")
            
                if amount_decimal.as_tuple().exponent < -self.SMALLEST_UNIT_EXPONENT:
                    raise ValueError("Amount has more than 8 decimal places")

                # Convert to satoshis
                satoshis = int(amount_decimal * self.SATOSHIS_PER_BITCOIN)
                if satoshis > self.MAX_BITCOIN * self.SATOSHIS_PER_BITCOIN:
                    raise ValueError("Amount exceeds maximum")
                
                self._put_with_validation(self.FIELD_AMOUNT, satoshis)
            except (InvalidOperation, ValueError, OverflowError) as e:
                raise BIP21Error(f"'{value}' is not a valid amount: {e}")
        
        elif name == self.FIELD_BC and value:
            # Parse bc parameter (Bech32m address) and add to list
            try:
                decoded_bc = unquote(value)
                # Basic validation for Bech32m address format (case-insensitive)
                if not decoded_bc.lower().startswith('bc1') and not decoded_bc.lower().startswith('tb1'):
                    raise ValueError("Bech32m address must start with 'bc1'/'tb1'")
                # Add to list of bc addresses (normalized to lowercase)
                self.parameters[self.FIELD_BC].append(decoded_bc.lower())
            except Exception as e:
                raise BIP21Error(f"'{value}' is not a valid Bech32m address: {e}")
        
        elif name == self.FIELD_SILENT_PAYMENT and value:
            # Parse silent payment address and add to list
            try:
                decoded_sp = unquote(value)
                # Basic validation for silent payment address format
                if not decoded_sp.startswith('sp1'):
                    raise ValueError("Silent payment address must start with 'sp1'")
                # Add to list of silent payment addresses
                self.parameters[self.FIELD_SILENT_PAYMENT].append(decoded_sp.lower())
            except Exception as e:
                raise BIP21Error(f"'{value}' is not a valid silent payment address: {e}")
        
        elif name.startswith("req-"):
            # Required parameter we don't know about
            raise BIP21Error(f"'{name}' is required but not known, this URI is not valid")
        
        else:
            # Known or unknown optional parameter
            if value:
                decoded_value = unquote(value)
                self._put_with_validation(name, decoded_value)
    
    def _put_with_validation(self, key: str, value: str):
        """Add parameter with duplicate validation for non-payment instruction fields"""
        if key in self.parameters and key not in self.PAYMENT_INSTRUCTION_FIELDS:
            raise BIP21Error(f"'{key}' is duplicated, URI is invalid")
        self.parameters[key] = value
    
    def get_address(self) -> str:
        """Get the Bitcoin address from the URI path"""
        return self.parameters.get("uri_address")
    
    def get_amount(self) -> int:
        """Get the amount in satoshis, or None if not specified"""
        return self.parameters.get(self.FIELD_AMOUNT)
    
    def get_label(self) -> str:
        """Get the label parameter"""
        return self.parameters.get(self.FIELD_LABEL)
    
    def get_message(self) -> str:
        """Get the message parameter"""
        return self.parameters.get(self.FIELD_MESSAGE)
    
    def get_bc_addresses(self) -> list[str]:
        """Get all bech32(m) addresses from the bc parameters"""
        return self.parameters.get(self.FIELD_BC, [])
    
    def get_silent_payment_addresses(self) -> list[str]:
        """Get all silent payment addresses from the sp parameters"""
        return self.parameters.get(self.FIELD_SILENT_PAYMENT, [])
    
    def get_parameter(self, name: str):
        """Get a parameter by name"""
        return self.parameters.get(name)
    
    def __str__(self) -> str:
        """String representation showing all parameters"""
        items = []
        for key, value in self.parameters.items():
            items.append(f"'{key}'='{value}'")
        return f"BitcoinURI[{','.join(items)}]"
    
    def to_uri_string(self) -> str:
        """Get the original URI string"""
        return self.uri_string
    
    @classmethod
    def from_address(cls, address: str):
        """Create a BitcoinURI from just an address"""
        return cls(f"{cls.BITCOIN_SCHEME}:{address}")
    
    @classmethod
    def from_silent_payment(cls, sp_address: str):
        """Create a BitcoinURI from a silent payment address"""
        encoded_sp = quote(sp_address, safe='')
        return cls(f"{cls.BITCOIN_SCHEME}:?{cls.FIELD_SILENT_PAYMENT}={encoded_sp}")
    
    @classmethod
    def build_uri(cls, address: str = None, amount: int = None, label: str = None, message: str = None, silent_payment: str = None) -> str:
        """
        Build a Bitcoin URI from components.
        
        Args:
            address: Bitcoin address (optional)
            amount: Amount in satoshis (optional)
            label: Label text (optional)
            message: Message text (optional)
            silent_payment: Silent payment address (optional)
            
        Returns:
            Complete Bitcoin URI string
        """
        if amount is not None and amount < 0:
            raise ValueError("Amount must be positive")
        
        # Handle silent payment URIs (no address in path)
        if silent_payment and not address:
            uri = f"{cls.BITCOIN_SCHEME}:"
        elif address:
            uri = f"{cls.BITCOIN_SCHEME}:{address}"
        else:
            uri = f"{cls.BITCOIN_SCHEME}:"
        
        params = []
        
        if silent_payment:
            encoded_sp = quote(silent_payment, safe='')
            params.append(f"{cls.FIELD_SILENT_PAYMENT}={encoded_sp}")
        
        if amount is not None:
            # Convert satoshis to BTC with proper decimal formatting
            btc_amount = Decimal(amount) / cls.SATOSHIS_PER_BITCOIN
            # Format to remove trailing zeros
            amount_str = f"{btc_amount:f}".rstrip('0').rstrip('.')
            params.append(f"{cls.FIELD_AMOUNT}={amount_str}")
        
        if label:
            encoded_label = quote(label, safe='')
            params.append(f"{cls.FIELD_LABEL}={encoded_label}")
        
        if message:
            encoded_message = quote(message, safe='')
            params.append(f"{cls.FIELD_MESSAGE}={encoded_message}")
        
        if params:
            uri += "?" + "&".join(params)
        
        return uri