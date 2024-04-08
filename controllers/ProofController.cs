using System.IdentityModel.Tokens.Jwt;
using AElf;
using Groth16.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
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
    private string IdentifierHash =
        "4d603a0116641104814928a5a5bbcb967f28418508345c20d1faf80bab6329c3";
    private string PublicKey =
        "3NXwASNf_7-9hOWDKyZ39qgz-yl_npuIsBgxnhNoE7WyQQl-muajPsQRdFqM-HWsAAbS_WtLrmf2aRSmjXBm8wXHIeJjcrZiWeUnSyfZLDr13jxXhN0rDvdiZEsAlaKuh-iCgwC_pXd0TtWpaYlv5FFguuSitKTOiDR6z3eSZUd0XNxr8POCDQ7VlG_4HyzhsO7nOwgivO-PzekDEbcoLI93U8uzKZXYHSRxYWhoSp47PbM9D5WbuwXqbmXRp9TjiJUy6GqEOJ4K2FNvqe-g6C3BnpPVuHZNaVf8QGP806rWrWPdJ0irGBhg-EasC-sdFSrH3kxMxBFfVsuj69U-7Q";

    public ProofController(ILogger<ProofController> logger, Prover prover)
    {
        _logger = logger;
        _prover = prover;
    }

    [HttpPost("generate")]
    public async Task<IActionResult> GenerateProof(ProofGenerationSchema.ProofGenerationRequest request)
    {
        try
        {
            var jwtHeader = request.Jwt.Split(".")[0];
            var jwtPayload = request.Jwt.Split(".")[1];
            var jwtSignature = request.Jwt.Split(".")[2];

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(request.Jwt);

            // get google public key from jwt
            var publicKey = await GetGooglePublicKeyFromJwt(jwt);
            // get guardianIdentifierHash from jwt
            var guardianIdentifierHash = GetGuardianIdentifierHashFromJwt(jwt, request.Salt);
            // google public key to hex
            var publicKeyHex = BitConverter
                .ToString(WebEncoders.Base64UrlDecode(publicKey)).Replace("-", "")
                .ToLower();
            // google public key hex to chunked bytes
            var pubkey = Helpers.HexToChunkedBytes(publicKeyHex, 121, 17)
                .Select(s => s.HexToBigInt()).ToList();
            // jwt signature to hex
            var signatureHex = BitConverter
                .ToString(WebEncoders.Base64UrlDecode(jwtSignature)).Replace("-", "")
                .ToLower();
            // jwt signature hex to chunked bytes
            var signature = Helpers.HexToChunkedBytes(signatureHex, 121, 17)
                .Select(s => s.HexToBigInt()).ToList();
            // salt hex to chunked bytes
            var salt = HexStringToByteArray(request.Salt).Select(b => b.ToString()).ToList();

            // build parameters of ProveBn254
            IDictionary<string, IList<string>> provingInput = new Dictionary<string, IList<string>>();
            provingInput["jwt"] = PadString(jwtHeader + "." + jwtPayload, 2048);
            provingInput["signature"] = signature;
            provingInput["pubkey"] = pubkey;
            provingInput["salt"] = salt;

            // exec ProveBn254
            var provingOutputString = _prover.ProveBn254(provingInput);
            var provingOutput = ParseProvingOutput(provingOutputString);
            // verify output
            var verified = Verifier.VerifyBn254(_prover.ExportVerifyingKeyBn254(), provingOutput.PublicInputs,
                provingOutput.Proof);
            return verified
                ? StatusCode(200, new ProofGenerationSchema.ProofGenerationResponse
                {
                    Proof = provingOutput.Proof,
                    IdentifierHash = guardianIdentifierHash,
                    PublicKey = publicKey
                })
                : StatusCode(500, "proof generate fail");
        }
        catch (Exception e)
        {
            _logger.LogError("proof generate exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }
    
    [HttpPost("generate-test")]
    public IActionResult GenerateProofTest(ProofGenerationSchema.ProofGenerationTestRequest request)
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
            return StatusCode(200, new ProofGenerationSchema.ProofGenerationResponse
            {
                Proof = ProofStr,
                IdentifierHash = IdentifierHash,
                PublicKey = PublicKey
            });
        }
        catch (Exception e)
        {
            _logger.LogError("proof generate exception, e: {msg}", e.Message);
            return StatusCode(500, e.Message);
        }
    }
    
    #region private method
    private static byte[] HexStringToByteArray(string hex)
    {
        var length = hex.Length;
        var byteArray = new byte[length / 2];

        for (var i = 0; i < length; i += 2)
        {
            byteArray[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }

        return byteArray;
    }

    private static string GetGuardianIdentifierHashFromJwt(JwtSecurityToken jwt, string salt)
    {
        var guardianIdentifier = jwt.Payload.Sub;
        var hash = HashHelper.ComputeFrom(guardianIdentifier).ToHex();
        var guardianIdentifierHash = HashHelper.ComputeFrom(salt + hash).ToHex();
        return guardianIdentifierHash;
    }

    private static async Task<string> GetGooglePublicKeyFromJwt(JwtSecurityToken jwt)
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
        var paddedBytes = str.Select(c => ((int) c).ToString()).ToList();

        var paddingLength = paddedBytesSize - paddedBytes.Count;
        if (paddingLength > 0)
        {
            paddedBytes.AddRange(Enumerable.Repeat("0", paddingLength));
        }

        return paddedBytes;
    }
    #endregion
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