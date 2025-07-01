using System;

namespace AspNetCore.EncryptRequest.Util.Models
{
    [Serializable]
    public class CipherKey
    {
        public string? Id { get; set; }

        public KeyTypeEnum KeyType { get; set; }

        public string? PublicKey { get; set; }

        public string? PrivateKey { get; set; }

        public override string ToString()
        {
            var info =
                $"({this.Id}): Public key {this.PublicKey},(Private key): {this.PrivateKey}";
            return info;
        }
    }
}