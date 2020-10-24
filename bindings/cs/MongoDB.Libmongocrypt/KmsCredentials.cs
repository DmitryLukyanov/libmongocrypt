using System;

namespace MongoDB.Libmongocrypt
{
    /// <summary>
    /// KMS Credentials.
    /// </summary>
    public class KmsCredentials
    {
        private readonly byte[] _credentialsBytes;

        /// <summary>
        /// Creates an <see cref="KmsCredentials"/> class.
        /// </summary>
        /// <param name="credentialsBytes">The bytes representation of credentials bson document.</param>
        public KmsCredentials(byte[] credentialsBytes)
        {
            _credentialsBytes = credentialsBytes ?? throw new ArgumentNullException(nameof(credentialsBytes));
        }

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
