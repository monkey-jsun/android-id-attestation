package net.junsun.idattestation;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Build;
import android.os.Bundle;
import android.security.KeyStoreParameter;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.attestation.AttestationApplicationId;
import com.google.android.attestation.AuthorizationList;
import com.google.android.attestation.ParsedAttestationRecord;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Optional;
import java.util.Random;

import javax.net.ssl.KeyStoreBuilderParameters;
import static com.google.android.attestation.ParsedAttestationRecord.createParsedAttestationRecord;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.bouncycastle.util.encoders.Base64.toBase64String;

public class MainActivity extends AppCompatActivity {

    TextView output;
    EditText alias;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        output=(TextView)findViewById(R.id.textViewOutput);
        alias=(EditText)findViewById(R.id.textViewAliasInput);

        ((Button)findViewById(R.id.buttonGenKey)).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                   genKey(alias.getText().toString());
                } catch (Exception ignore) {}
            }
        });

        ((Button)findViewById(R.id.buttonGetKey)).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    getKey(alias.getText().toString());
                } catch (Exception ignore) {}
            }
        });

        ((Button)findViewById(R.id.buttonDelKey)).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    delKey(alias.getText().toString());
                } catch (Exception ignore) {}
            }
        });
        myprint("app starting ...\n");
    }

    @RequiresApi(api = Build.VERSION_CODES.N)
    private void genKey(String alias ) throws Exception {
        if (alias.isEmpty()) {
            Toast.makeText(this,"alias is empty. quitting ...", Toast.LENGTH_SHORT).show();
            return;
        }
        myprint("Generating key '" + alias + "' ...");

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        if (keyStore.containsAlias(alias)) {
            myprint("Key '" + alias + "' already exists in keystore. quitting...\n");
            return;
        }

        // we now generate the key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        byte[] challengeBytes = "hello, this is challenge phrase [jsun]".getBytes();
        keyPairGenerator.initialize(
                new KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        //.setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                        //.setDigests(KeyProperties.DIGEST_SHA256,
                        //        KeyProperties.DIGEST_SHA384,
                        //        KeyProperties.DIGEST_SHA512)
                        // Only permit the private key to be used if the user authenticated
                        // within the last five minutes.
                        //.setUserAuthenticationRequired(true)
                        //.setUserAuthenticationValidityDurationSeconds(5 * 60)
                        .setKeySize(256)
                        .setAttestationChallenge(challengeBytes)
                        .build());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        myprint("Key '" + alias + "' is successfully created. \n");
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void getKey(String alias )
            throws Exception {
        if (alias.isEmpty()) {
            Toast.makeText(this, "alias is empty. quitting ...", Toast.LENGTH_SHORT).show();
            return;
        }
        myprint("Getting key '" + alias + "' ...");

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        
        if (!keyStore.containsAlias(alias)) {
            myprint("Key '" + alias + "' does not exist in keystore. quitting...\n");
            return;
        }

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();

        myprint("found the key with alias '" + alias + "' ...");
        myprint("private key : " + privateKey.toString());
        myprint("public key : " + new String(Base64.encode(publicKey.getEncoded(),0)));

        myprint("what is happening ...");

        final Certificate[] attestationCertificates = keyStore.getCertificateChain(alias);
        myprint("number certificates in the chain is " + attestationCertificates.length);

        ParsedAttestationRecord parsedAttestationRecord = createParsedAttestationRecord((X509Certificate)attestationCertificates[0]);

        myprint("Attestation version: " + parsedAttestationRecord.attestationVersion);
        myprint("Attestation Security Level: " + parsedAttestationRecord.attestationSecurityLevel.name());
        myprint("Keymaster Version: " + parsedAttestationRecord.keymasterVersion);
        myprint("Keymaster Security Level: " + parsedAttestationRecord.keymasterSecurityLevel.name());
        myprint("Attestation Challenge: "
                + new String(parsedAttestationRecord.attestationChallenge, UTF_8));
        myprint("Unique ID: " + Arrays.toString(parsedAttestationRecord.uniqueId));

        myprint("=========\nSoftware Enforced Authorization List:");
        AuthorizationList softwareEnforced = parsedAttestationRecord.softwareEnforced;
        printAuthorizationList(softwareEnforced, "\t");

        myprint("=========\nTEE Enforced Authorization List:");
        AuthorizationList teeEnforced = parsedAttestationRecord.teeEnforced;
        printAuthorizationList(teeEnforced, "\t");

    }

    private  void printAuthorizationList(AuthorizationList authorizationList, String indent) {
        // Detailed explanation of the keys and their values can be found here:
        // https://source.android.com/security/keystore/tags
        printOptional(authorizationList.purpose, indent + "Purpose(s)");
        printOptional(authorizationList.algorithm, indent + "Algorithm");
        printOptional(authorizationList.keySize, indent + "Key Size");
        printOptional(authorizationList.digest, indent + "Digest");
        printOptional(authorizationList.padding, indent + "Padding");
        printOptional(authorizationList.ecCurve, indent + "EC Curve");
        printOptional(authorizationList.rsaPublicExponent, indent + "RSA Public Exponent");
        myprint(indent + "Rollback Resistance: " + authorizationList.rollbackResistance);
        printOptional(authorizationList.activeDateTime, indent + "Active DateTime");
        printOptional(
                authorizationList.originationExpireDateTime, indent + "Origination Expire DateTime");
        printOptional(authorizationList.usageExpireDateTime, indent + "Usage Expire DateTime");
        myprint(indent + "No Auth Required: " + authorizationList.noAuthRequired);
        printOptional(authorizationList.userAuthType, indent + "User Auth Type");
        printOptional(authorizationList.authTimeout, indent + "Auth Timeout");
        myprint(indent + "Allow While On Body: " + authorizationList.allowWhileOnBody);
        myprint(
                indent
                        + "Trusted User Presence Required: "
                        + authorizationList.trustedUserPresenceRequired);
        myprint(
                indent + "Trusted Confirmation Required: " + authorizationList.trustedConfirmationRequired);
        myprint(
                indent + "Unlocked Device Required: " + authorizationList.unlockedDeviceRequired);
        myprint(indent + "All Applications: " + authorizationList.allApplications);
        printOptional(authorizationList.applicationId, indent + "Application ID");
        printOptional(authorizationList.creationDateTime, indent + "Creation DateTime");
        printOptional(authorizationList.origin, indent + "Origin");
        myprint(indent + "Rollback Resistant: " + authorizationList.rollbackResistant);
        /*if (authorizationList.rootOfTrust.isPresent()) {
            myprint(indent + "Root Of Trust:");
            printRootOfTrust(authorizationList.rootOfTrust, indent + "\t");
        }*/
        printOptional(authorizationList.osVersion, indent + "OS Version");
        printOptional(authorizationList.osPatchLevel, indent + "OS Patch Level");
        if (authorizationList.attestationApplicationId.isPresent()) {
            myprint(indent + "Attestation Application ID:");
            printAttestationApplicationId(authorizationList.attestationApplicationId, indent + "\t");
        }
        printOptional(
                authorizationList.attestationApplicationIdBytes,
                indent + "Attestation Application ID Bytes");

        if (authorizationList.attestationIdBrand.isPresent())
                myprint(indent + "Attestation ID Brand:" + new String(authorizationList.attestationIdBrand.get(), UTF_8));
        if (authorizationList.attestationIdDevice.isPresent())
                myprint(indent + "Attestation ID Device:" + new String(authorizationList.attestationIdDevice.get(), UTF_8));
        if (authorizationList.attestationIdProduct.isPresent())
                myprint(indent + "Attestation ID Product:" + new String(authorizationList.attestationIdProduct.get(), UTF_8));
        if (authorizationList.attestationIdSerial.isPresent())
                myprint(indent + "Attestation ID Serial:" + new String(authorizationList.attestationIdSerial.get(), UTF_8));
        if (authorizationList.attestationIdImei.isPresent())
                myprint(indent + "Attestation ID IMEI:" + new String(authorizationList.attestationIdImei.get(), UTF_8));
        if (authorizationList.attestationIdMeid.isPresent())
                myprint(indent + "Attestation ID MEID:" + new String(authorizationList.attestationIdMeid.get(), UTF_8));
        if (authorizationList.attestationIdManufacturer.isPresent())
                myprint(indent + "Attestation ID Manufacturer:" + new String(authorizationList.attestationIdManufacturer.get(), UTF_8));
        if (authorizationList.attestationIdModel.isPresent())
                myprint(indent + "Attestation ID Model:" + new String(authorizationList.attestationIdModel.get(), UTF_8));

        printOptional(authorizationList.vendorPatchLevel, indent + "Vendor Patch Level");
        printOptional(authorizationList.bootPatchLevel, indent + "Boot Patch Level");
    }

    private  <T> void printOptional(Optional<T> optional, String caption) {
        if (optional.isPresent()) {
            if (optional.get() instanceof byte[]) {
                myprint(caption + ": " + toBase64String((byte[]) optional.get()));
            } else {
                myprint(caption + ": " + optional.get());
            }
        }
        else
            myprint(caption + ": NOT PRESENT");
    }
    @RequiresApi(api = Build.VERSION_CODES.M)
    private void delKey(String alias )
            throws Exception {
        if (alias.isEmpty()) {
            Toast.makeText(this, "alias is empty. quitting ...", Toast.LENGTH_SHORT).show();
            return;
        }
        myprint("Deleting key '" + alias + "' ...\n");

        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        if (!keyStore.containsAlias(alias)) {
            myprint("Key '" + alias + "' does not exist in keystore. quitting...\n");
            return;
        }

        keyStore.deleteEntry(alias);
        myprint("Key '" + alias + "' is deleted!\n");
    }

    private void printAttestationApplicationId(
            Optional<AttestationApplicationId> attestationApplicationId, String indent) {
        if (attestationApplicationId.isPresent()) {
            myprint(indent + "Package Infos (<package name>, <version>): ");
            for (AttestationApplicationId.AttestationPackageInfo info : attestationApplicationId.get().packageInfos) {
                myprint(indent + "\t" + info.packageName + ", " + info.version);
            }
            myprint(indent + "Signature Digests:");
            for (byte[] digest : attestationApplicationId.get().signatureDigests) {
                myprint(indent + "\t" + Base64.encodeToString(digest, Base64.DEFAULT));
            }
        }
    }

    private void myprint(String msg) {
        output.append(msg + "\n");
    }
}
