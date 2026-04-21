from datetime import datetime                                                                                                                                           
                                                                                                                                                                        
from pydantic import BaseModel                                                                                                                                          
                                                                                                                                                                      
                                                                                                                                                                      
class TlsAuditRequest(BaseModel):                                                                                                                                       
    hosts: list[str] = []                                                                                                                                               
    session_id: int | None = None                                                                                                                                       
    analysis_id: int | None = None                                                                                                                                      
    port: int = 443                                                                                                                                                     
                                                                                                                                                                                                                                                                                                                                            
class TlsAuditOut(BaseModel):                                                                                                                                           
    id: int                                                                                                                                                             
    host: str                                                                                                                                                           
    port: int                                                                                                                                                           
    session_id: int | None                                                                                                                                              
    analysis_id: int | None                                                                                                                                             
    audited_at: datetime                                                                                                                                                
    status: str                                                                                                                                                         
    cert_subject: str | None                                                                                                                                            
    cert_issuer: str | None                                                                                                                                             
    cert_expiry: str | None                                                                                                                                             
    cert_self_signed: bool | None                                                                                                                                       
    tls10_enabled: bool                                                                                                                                                 
    tls11_enabled: bool                                                                                                                                                 
    tls12_enabled: bool                                                                                                                                                 
    tls13_enabled: bool                                                                                                                                                 
    hsts_present: bool                                                                                                                                                  
    weak_ciphers: str | None                                                                                                                                            
    findings_json: str | None                                                                                                                                           
    error: str | None                                                                                                                                                   
                                                                                                                                                                     
    model_config = {"from_attributes": True}    