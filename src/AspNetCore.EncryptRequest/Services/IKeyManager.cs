using System.Threading.Tasks;
using AspNetCore.EncryptRequest.Util.Models;

namespace AspNetCore.EncryptRequest.Services
{
    public interface IKeyManager
    {
        Task<CipherKey?> GetKeyAsync(KeyTypeEnum keyType);

        Task<string?> GetPrivateKeyAsync(KeyTypeEnum keyType);

        Task<string?> GetPublicKeyAsync(KeyTypeEnum keyType);

        Task SaveKeyAsync(CipherKey key);

        Task<CipherKey> CreateDefaultAsymmetricKey(KeyTypeEnum keyType, bool isIncludePrivateKey = true);
    }
}