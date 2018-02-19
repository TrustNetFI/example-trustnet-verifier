package fi.trustnet.example.verifier;

import java.io.FileReader;
import java.net.URI;
import java.util.LinkedHashMap;

import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.core.Base58;

import com.github.jsonldjava.utils.JsonUtils;

import fi.trustnet.verifiablecredentials.VerifiableCredential;
import info.weboftrust.ldsignatures.validator.Ed25519Signature2018LdValidator;
import uniresolver.client.ClientUniResolver;
import uniresolver.did.DIDDocument;
import uniresolver.result.ResolutionResult;

public class ExampleVerifier {

	public static void main(String[] args) throws Exception {

		// parse verifiable credential

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromReader(new FileReader("verifiablecredential.jsonld"));
		VerifiableCredential verifiableCredential = VerifiableCredential.fromJsonLdObject(jsonLdObject);

		// discover issuer public key

		byte[] issuerPublicKey;

		ClientUniResolver clientUniResolver = new ClientUniResolver();
		clientUniResolver.setResolveUri("https://uniresolver.io/1.0/identifiers/");

		URI issuer = verifiableCredential.getIssuer();
		System.out.println("Issuer DID: " + issuer.toString());

		ResolutionResult resolutionResult = clientUniResolver.resolve(issuer.toString());
		System.out.println(resolutionResult.toJson());
		DIDDocument didDocument = resolutionResult.getDidDocument();
		System.out.println(JsonUtils.toPrettyString(didDocument.getJsonLdObject()));
		String issuerPublicKeyBase58 = didDocument.getPublicKeys().get(0).getPublicKeyBase58();
		issuerPublicKey = Base58.decode(issuerPublicKeyBase58);
		System.out.println("Issuer Public Key: " + Hex.encodeHexString(issuerPublicKey));

		// verify verifiable credential

		Ed25519Signature2018LdValidator validator = new Ed25519Signature2018LdValidator(issuerPublicKey);
		boolean validate = validator.validate(verifiableCredential.getJsonLdObject());

		// output

		System.out.println(validate);
	}
}
