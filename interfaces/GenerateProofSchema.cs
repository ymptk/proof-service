using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace ProofService.interfaces;

public abstract class ProofGenerationSchema
{
    public class ProofGenerationRequest
    {
        [JsonPropertyName("jwt")]
        public List<string> Jwt { get; set; }
        
        [JsonPropertyName("signature")]
        public List<string> Signature { get; set; }
        
        [JsonPropertyName("pubkey")]
        public List<string> Pubkey { get; set; }
        
        [JsonPropertyName("salt")]
        public List<string> Salt { get; set; }
    }
    
    public class ProofGenerationRequest2
    {
        [JsonPropertyName("jwt")]
        public string Jwt { get; set; }
        
        [JsonPropertyName("salt")]
        public string Salt { get; set; }
        
        [JsonPropertyName("identifierHash")]
        public string IdentifierHash { get; set; }
    }
    
    public class ProofGenerationResponse
    {
        [JsonPropertyName("proof")]
        public string Proof { get; set; }
    }
}