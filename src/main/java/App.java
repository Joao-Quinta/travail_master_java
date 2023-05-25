/*
 * Copyright IBM Corp. All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.TlsChannelCredentials;
import org.hyperledger.fabric.client.CommitException;
import org.hyperledger.fabric.client.CommitStatusException;
import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.EndorseException;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.GatewayException;
import org.hyperledger.fabric.client.SubmitException;
import org.hyperledger.fabric.client.identity.Identities;
import org.hyperledger.fabric.client.identity.Identity;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.Signers;
import org.hyperledger.fabric.client.identity.X509Identity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

public final class App {
    public static void main(String[] args) {
        System.out.println("App is running!");
        final Path CRYPTO_PATH =Paths.get("/home/fabric/go/src/github.com/Joao-Quinta/2-fabric-samples/test-network/organizations/peerOrganizations/org1.example.com");
        final
    }
}

/* 
try {
            String certificatePem = Files.readString(certificatePath, StandardCharsets.UTF_8);
            byte[] privateKeyPem = Files.readAllBytes(privateKeyPath);

            // Create an X.509 Identity
            X509Identity identity = Identities.newX509Identity("Org1MSP", certificatePem);

            // Create a signer
            Signer signer = Signers.newPrivateKeySigner(privateKeyPem);

            // Rest of your code...

        } catch (IOException e) {
            e.printStackTrace();
        }
*/