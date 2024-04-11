using System.Text.Json.Serialization;

namespace ProofService.interfaces;

public abstract class ProofGenerationSchema
{
    public class ProofGenerationTestRequest
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
    
    public class ProofGenerationRequest
    {
        [JsonPropertyName("jwt")]
        public string Jwt { get; set; }
        
        [JsonPropertyName("salt")]
        public string Salt { get; set; }
    }
    
    public class ProofGenerationResponse
    {
        [JsonPropertyName("proof")]
        public string Proof { get; set; }
        
        [JsonPropertyName("identifierHash")]
        public string IdentifierHash { get; set; }
        
        [JsonPropertyName("publicKey")]
        public string PublicKey { get; set; }
    }
    
    public class InitializeRequest
    {
        [JsonPropertyName("endpoint")]
        public string Endpoint { get; set; }
        
        [JsonPropertyName("contractAddress")]
        public string ContractAddress { get; set; }
        
        [JsonPropertyName("walletAddress")]
        public string WalletAddress { get; set; }
        
        [JsonPropertyName("pk")]
        public string Pk { get; set; }
        
        [JsonPropertyName("publicKey")]
        public string PublicKey { get; set; }

        [JsonPropertyName("vk")]
        public string Vk { get; set; }
    }
    
    public class CreateTestRequest
    {
        [JsonPropertyName("guardianApproved")]
        public GuardianApproved GuardianApproved { get; set; }
        
        [JsonPropertyName("managerInfo")]
        public ManagerInfo ManagerInfo { get; set; }
    }
    
    public class GuardianApproved
    {
        [JsonPropertyName("endpoint")]
        public string Endpoint { get; set; }
        
        [JsonPropertyName("contractAddress")]
        public string ContractAddress { get; set; }
    }
    
    public class ZkGuardianInfo
    {
        [JsonPropertyName("endpoint")]
        public string Endpoint { get; set; }
        
        [JsonPropertyName("contractAddress")]
        public string ContractAddress { get; set; }
    }
    
    public class ManagerInfo
    {
        [JsonPropertyName("endpoint")]
        public string Endpoint { get; set; }
        
        [JsonPropertyName("contractAddress")]
        public string ContractAddress { get; set; }
    }
}