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

public class ExampleVerifier {

	public static void main(String[] args) throws Exception {

		// parse verifiable credential

		LinkedHashMap<String, Object> jsonLdObject = (LinkedHashMap<String, Object>) JsonUtils.fromReader(new FileReader("verifiablecredential.jsonld"));
		VerifiableCredential verifiableCredential = VerifiableCredential.fromJsonLdObject(jsonLdObject);

		// discover issuer public key

		byte[] issuerPublicKey;

		ClientUniResolver clientUniResolver = new ClientUniResolver();
		clientUniResolver.setResolverUri("https://uniresolver.io/1.0/identifiers/");

		URI issuer = verifiableCredential.getIssuer();
		System.out.println("Issuer DID: " + issuer.toString());

		DIDDocument didDocument = clientUniResolver.resolve(issuer.toString()).getResult();
		System.out.println(JsonUtils.toPrettyString(didDocument.getJsonLdObject()));
		String issuerPublicKeyBase64 = didDocument.getPublicKeys().get(0).getPublicKeyBase64();
		issuerPublicKey = Base58.decode(issuerPublicKeyBase64);
		System.out.println("Issuer Public Key: " + Hex.encodeHexString(issuerPublicKey));

		// verify verifiable credential

		Ed25519Signature2018LdValidator validator = new Ed25519Signature2018LdValidator(issuerPublicKey);
		boolean validate = validator.validate(verifiableCredential.getJsonLdObject());

		// output

		System.out.println(validate);
	}
}
