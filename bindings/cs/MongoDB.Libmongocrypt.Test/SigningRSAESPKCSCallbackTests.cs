/*
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
using System.Text;
using FluentAssertions;
using Xunit;

namespace MongoDB.Libmongocrypt.Test
{
    public class SigningRSAESPKCSCallbackTests
    {
        private static string DataToSign =  "data to sign";

        private static string PrivateKey = Environment.GetEnvironmentVariable("FLE_GCP_RSA_SIGNING_PKCS8_PRIVATE_KEY") ?? throw new ArgumentNullException("FLE_GCP_RSA_SIGNING_PKCS8_PRIVATE_KEY has not been specified.");

        private static string ExpectedSignature = "VocBRhpMmQ2XCzVehWSqheQLnU889gf3dhU4AnVnQTJjsKx/CM23qKDPkZDd2A/BnQsp99SN7ksIX5Raj0TPw"
            + "yN5OCN/YrNFNGoOFlTsGhgP/hyE8X3Duiq6sNO0SMvRYNPFFGlJFsp1Fw3Z94eYMg4/Wpw5s4+Jo5Zm/qY7aTJIqDKDQ3CNHLeJgcMUOc9sz01/GzoUYKDVODHSx"
            + "rYEk5ireFJFz9vP8P7Ha+VDUZuQIQdXer9NBbGFtYmWprY3nn4D3Dw93Sn0V0dIqYeIo91oKyslvMebmUM95S2PyIJdEpPb2DJDxjvX/0LLwSWlSXRWy9gapWoBk"
            + "b4ynqZBsg==";

        [Fact()]
        public void GetSignatureTest()
        {
            byte[] privateKeyBytes = Convert.FromBase64String(PrivateKey);
            var dataBytes = Encoding.ASCII.GetBytes(DataToSign);
            byte[] signature = SigningRSAESPKCSCallback.HashAndSignBytes(dataBytes, privateKeyBytes);
            string output = Convert.ToBase64String(signature);

            output.Should().Be(ExpectedSignature);
        }
    }
}
