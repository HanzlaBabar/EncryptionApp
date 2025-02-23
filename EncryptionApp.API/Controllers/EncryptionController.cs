using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Formatters;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionApp.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class EncryptionController : Controller
    {
        // key = AAECAwQFBgcICQoLDA0ODw==
        public EncryptionController(IConfiguration configuration)
        {
        }

        [HttpPost("encrypt")]
        public IActionResult Encrypt(string plainText, string key)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                return BadRequest(new { error = "Text to encrypt is required" });
            }

            try
            {
                string encryptedText = string.Empty;

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Convert.FromBase64String(key);
                    aesAlg.IV = new byte[16];

                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
                            csEncrypt.Write(plaintextBytes, 0, plaintextBytes.Length);
                            csEncrypt.FlushFinalBlock();
                            encryptedText = Convert.ToBase64String(msEncrypt.ToArray());
                        }
                    }
                }

                return Ok(encryptedText);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }

        [HttpPost("decrypt")]
        public IActionResult Decrypt(string cipherText, string key)
        {
            if (string.IsNullOrEmpty(cipherText))
            {
                return BadRequest(new { error = "Text to encrypt is required" });
            }
            try
            {
                string decryptedText = string.Empty;
                byte[] cipherTextByptes = Convert.FromBase64String(cipherText);

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = Convert.FromBase64String(key);
                    aesAlg.IV = new byte[16];

                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                    using(MemoryStream msDecrypt  = new MemoryStream(cipherTextByptes))
                    {
                        using(CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {

                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                decryptedText = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }

                return Ok(decryptedText);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = ex.Message });
            }
        }
    }
}
