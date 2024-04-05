using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Groth16.Net;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using ProofService.interfaces;
using RestSharp;

namespace ProofService.controllers;

[Route("proof")]
[ApiController]
public class ProofController : ControllerBase
{
    private readonly ILogger<ProofController> _logger;
    private readonly Prover _prover;

    private string ProofStr =
        "e4f43e941f23f1478ffd459a9f6ec97e60ad790467bb9ffca97d7865ac5df09953cbaf72d64482095954e1770b249de00e405b2c5ac47b601850cac0939749183f8447be0c6b3e44e7bb61100b1f6b0fac038ea4f56271c45f2a3ebe79a367034aa423bf11f4dc3ab21440dd6642255d4a50d843a3db42fc3fa79852adec062f";

    public ProofController(ILogger<ProofController> logger, Prover prover)
    {
        _logger = logger;
        _prover = prover;
    }

    [HttpPost("generate")]
    public IActionResult GenerateProof(ProofGenerationSchema.ProofGenerationRequest request)
    {
        try
        {
            IDictionary<string, IList<string>> provingInput = new Dictionary<string, IList<string>>();
            provingInput["jwt"] = request.Jwt;
            provingInput["signature"] = request.Signature;
            provingInput["pubkey"] = request.Pubkey;
            provingInput["salt"] = request.Salt;

            var provingOutputString = _prover.ProveBn254(provingInput);
            var provingOutput = ParseProvingOutput(provingOutputString);
            var verified = Verifier.VerifyBn254(_prover.ExportVerifyingKeyBn254(), provingOutput.PublicInputs,
                provingOutput.Proof);
            return verified
                ? StatusCode(200, new ProofGenerationSchema.ProofGenerationResponse {Proof = provingOutput.Proof})
                : StatusCode(500, "proof generate fail");
        }
        catch (Exception e)
        {
            _logger.LogError("proof generate exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }

    [HttpPost("generate-mock")]
    public IActionResult GenerateProofMock(ProofGenerationSchema.ProofGenerationRequest request)
    {
        try
        {
            return StatusCode(200, new ProofGenerationSchema.ProofGenerationResponse {Proof = ProofStr});
        }
        catch (Exception e)
        {
            _logger.LogError("proof generate exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }
    
    [HttpPost("generate-test")]
    public async Task<IActionResult> GenerateProofTest(ProofGenerationSchema.ProofGenerationRequest2 request)
    {
        try
        {
            var jwtHeader = request.Jwt.Split(".")[0];
            var jwtPayload = request.Jwt.Split(".")[1];
            var jwtSignature = request.Jwt.Split(".")[2];

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(request.Jwt);

            var publicKey = await GetGooglePublicKey(jwt);

            // var identifierHash = Helpers.HexStringToByteArray(request.IdentifierHash);
            // var salt = Helpers.HexStringToByteArray(request.Salt);
            var pk = Helpers.HexToChunkedBytes(publicKey, 121, 17)
                .Select(s => s.HexToBigInt()).ToList();
            var sign = Helpers.HexToChunkedBytes(jwtSignature, 121, 17)
                .Select(s => s.HexToBigInt()).ToList();

            IDictionary<string, IList<string>> provingInput = new Dictionary<string, IList<string>>();
            provingInput["jwt"] = PadString(jwtHeader + jwtPayload, 2048);
            provingInput["signature"] = sign;
            provingInput["pubkey"] = pk;
            provingInput["salt"] = PadString(request.Salt, 32);

            var provingOutputString = _prover.ProveBn254(provingInput);
            var provingOutput = ParseProvingOutput(provingOutputString);
            var verified = Verifier.VerifyBn254(_prover.ExportVerifyingKeyBn254(), provingOutput.PublicInputs,
                provingOutput.Proof);
            return verified
                ? StatusCode(200, new ProofGenerationSchema.ProofGenerationResponse {Proof = provingOutput.Proof})
                : StatusCode(500, "proof generate fail");
        }
        catch (Exception e)
        {
            _logger.LogError("proof generate exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }

    private static string ParseJwtPayload(string payload)
    {
        string padded = payload.Length % 4 == 0 ? payload : payload + "====".Substring(payload.Length % 4);
        string base64 = padded.Replace("_", "/").Replace("-", "+");
        byte[] outputb = Convert.FromBase64String(base64);
        string outStr = Encoding.Default.GetString(outputb);
        Console.WriteLine(outStr);
        return outStr;
    }

    private static async Task<string> GetGooglePublicKey(JwtSecurityToken jwt)
    {
        var options = new RestClientOptions("https://www.googleapis.com/oauth2/v3/certs");
        var client = new RestClient(options);
        var request = new RestRequest();
        var response = await client.GetAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            return "";
        }

        var res = (JObject) JsonConvert.DeserializeObject(response.Content);
        var keys = res["keys"];
        foreach (var key in keys)
        {
            var kid = key["kid"].ToString();
            if (jwt.Header.Kid == kid)
            {
                return key["n"].ToString();
            }
        }

        return "";
    }

    private static ProvingOutput ParseProvingOutput(string provingOutput)
    {
        return JsonConvert.DeserializeObject<ProvingOutput>(provingOutput);
    }

    private static List<string> PadString(string str, int paddedBytesSize)
    {
        List<string> paddedBytes = str.Select(c => ((int) c).ToString()).ToList();

        int paddingLength = paddedBytesSize - paddedBytes.Count;
        if (paddingLength > 0)
        {
            paddedBytes.AddRange(Enumerable.Repeat("0", paddingLength));
        }

        return paddedBytes;
    }
}

public class ProvingOutput
{
    public ProvingOutput(IList<string> publicInputs, string proof)
    {
        PublicInputs = publicInputs;
        Proof = proof;
    }

    [JsonProperty("public_inputs")] public IList<string> PublicInputs { get; set; }

    [JsonProperty("proof")] public string Proof { get; set; }

    public static ProvingOutput FromJsonString(string jsonString)
    {
        return JsonConvert.DeserializeObject<ProvingOutput>(jsonString);
    }
}