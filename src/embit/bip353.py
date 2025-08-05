import json
from . import bip21
from .util.dnssec_prover import verify_byte_stream


def verify_dns_proof(hrn: str, proof: bytes):
    """
    Verify a DNS proof for a given human-readable name.
    
    Args:
        hrn: Human-readable name to resolve from the proof
        proof: The DNS proof to verify
    
    Returns:
        Dictionary containing verification result with only TXT records
    """
    try:
        result = verify_byte_stream(proof, hrn)
        parsed_result = json.loads(result)
        
        # Filter to only include TXT records
        if "verified_rrs" in parsed_result:
            txt_records = [rr for rr in parsed_result["verified_rrs"] if rr.get("type") == "txt"]
            parsed_result["verified_rrs"] = txt_records
        
        return parsed_result
    except Exception as e:
        return {"error": f"DNSSEC proof verification failed for HRN '{hrn}': {e}"}


def get_payment_info_from_hrn(hrn: str, proof: bytes):
    """
    Extract complete payment information from a human-readable name using DNS proof verification.
    
    This function returns all available information from the Bitcoin URI, including
    traditional addresses, silent payment addresses, amounts, labels, etc.
    Only processes TXT records from DNS proof.
    
    Args:
        hrn: Human-readable name to resolve
        proof: DNS proof bytes
    
    Returns:
        Dictionary containing all payment information from the URI.
    """
    result = verify_dns_proof(hrn, proof)
    
    if "error" in result:
        raise Exception(result["error"])
    
    # Extract the Bitcoin URI from the verified TXT DNS records only
    verified_rrs = result.get("verified_rrs", [])
    txt_records = [rr for rr in verified_rrs if rr.get("type") == "txt"]
    
    if not txt_records:
        raise Exception(f"No TXT records found in DNSSEC proof for HRN '{hrn}'. BIP353 requires Bitcoin payment information to be stored in TXT records.")
    
    if len(txt_records) > 1:
        raise Exception(f"Multiple TXT records found for HRN '{hrn}'. BIP353 requires exactly one TXT record containing Bitcoin payment information.")
    
    try:
        bitcoin_uri_obj = bip21.BitcoinURI(txt_records[0]["contents"])
    except Exception as e:
        raise Exception(f"Invalid Bitcoin URI in TXT record for HRN '{hrn}': {e}")
    
    payment_info = {
        "uri": txt_records[0]["contents"],
        "hrn": txt_records[0]["name"],
        "address": bitcoin_uri_obj.get_address(),
        "silent_payment_address": bitcoin_uri_obj.get_silent_payment_address(),
    }

    # Validate that at least one payment method is available
    has_regular_address = payment_info["address"] is not None
    has_silent_payment = payment_info["silent_payment_address"] is not None
    
    if not has_regular_address and not has_silent_payment:
        raise Exception(f"Bitcoin URI in HRN '{hrn}' must contain either a regular Bitcoin address or a silent payment address")
    
    # Remove None values to clean up the response
    return {k: v for k, v in payment_info.items() if v is not None}