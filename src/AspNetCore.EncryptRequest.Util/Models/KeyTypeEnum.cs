﻿namespace AspNetCore.EncryptRequest.Util.Models
{
    /// <summary>
    /// Key type
    /// </summary>
    public enum KeyTypeEnum
    {
        /// <summary>
        /// Secret key
        /// </summary>
        SharedSecret = 1,

        /// <summary>
        /// TripleDES key
        /// </summary>
        TripleDES,

        /// <summary>
        /// RSA
        /// </summary>
        RSA
    }
}
