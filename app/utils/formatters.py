from typing import Any, Dict 

def success_response(data: Any, message: str = "success") -> Dict:  
    return { "status": "success", "message": message, "data": data } 

def error_response(message: str = "error") -> Dict:  
    return { "status": "error", "message": message, "data": None } 

def honey_response(is_real: bool, data: dict) -> Dict:  
    """ 
    Normalize honey encryption output 
    """  
    return { "status": "real" if is_real else "fake", "data": data } 