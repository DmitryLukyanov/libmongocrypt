using System;

namespace MongoDB.Libmongocrypt
{
    /// <summary>
    /// KMS Credentials.
    /// </summary>
    public class KmsCredentials
    {
        private readonly byte[] _credentialsBytes;
        private readonly KmsType _kmsType;

        /// <summary>
        /// Creates an <see cref="KmsCredentials"/> class.
        /// </summary>
        /// <param name="kmsType">The kms type.</param>
        /// <param name="credentialsBytes">The bytes representation of credentials bson document.</param>
        public KmsCredentials(KmsType kmsType, byte[] credentialsBytes)
        {
            _credentialsBytes = credentialsBytes ?? throw new ArgumentNullException(nameof(credentialsBytes));
            _kmsType = kmsType;
        }

        public KmsType KmsType => _kmsType;

        // internal methods
        internal void SetCredentials(MongoCryptSafeHandle handle, Status status)
        {
            unsafe
            {
                fixed (byte* p = _credentialsBytes)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)_credentialsBytes.Length))
                    {
                        handle.Check(status, Library.mongocrypt_setopt_kms_providers(handle, pinned.Handle));
                    }
                }
            }
        }
    }
}
