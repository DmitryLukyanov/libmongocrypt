﻿/*
 * Copyright 2020–present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections.Generic;
using System.Linq;

namespace MongoDB.Libmongocrypt
{
    /// <summary>
    /// Represent a kms key.
    /// </summary>
    public class KmsKeyId : IKmsKeyId, IInternalKmsKeyId
    {
        private readonly IReadOnlyList<byte[]> _alternateKeyNameBytes;
        private readonly byte[] _dataKeyOptionsBytes;
        private readonly KmsType _kmsType;

        /// <summary>
        /// Creates an <see cref="KmsKeyId"/> class.
        /// </summary>
        /// <param name="kmsType">The kms type.</param>
        /// <param name="dataKeyOptionsBytes">The bytes representation of dataOptions bson document.</param>
        /// <param name="alternateKeyNameBytes">The bytes representation of alternate keyName.</param>
        public KmsKeyId(
            KmsType kmsType,
            byte[] dataKeyOptionsBytes,
            IEnumerable<byte[]> alternateKeyNameBytes = null)
        {
            _kmsType = kmsType;
            _dataKeyOptionsBytes = dataKeyOptionsBytes ?? throw new ArgumentNullException(nameof(dataKeyOptionsBytes));
            _alternateKeyNameBytes = (alternateKeyNameBytes ?? Enumerable.Empty<byte[]>()).ToList().AsReadOnly();
        }

        /// <inheritdoc />
        public IReadOnlyList<byte[]> AlternateKeyNameBytes => _alternateKeyNameBytes;

        /// <inheritdoc />
        public KmsType KeyType => _kmsType;

        /// <inheritdoc />
        void IInternalKmsKeyId.SetCredentials(ContextSafeHandle context, Status status)
        {
            unsafe
            {
                fixed (byte* p = _dataKeyOptionsBytes)
                {
                    IntPtr ptr = (IntPtr)p;
                    using (PinnedBinary pinned = new PinnedBinary(ptr, (uint)_dataKeyOptionsBytes.Length))
                    {
                        context.Check(status, Library.mongocrypt_ctx_setopt_key_encryption_key(context, pinned.Handle));
                    }
                }
            }
            ((IInternalKmsKeyId)this).SetAlternateKeyNames(context, status);
        }

        /// <inheritdoc />
        void IInternalKmsKeyId.SetAlternateKeyNames(ContextSafeHandle context, Status status)
        {
            this.SetAlternateKeyNames(context, status);
        }
    }
}
