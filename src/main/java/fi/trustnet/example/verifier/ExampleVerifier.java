package fi.trustnet.example.verifier;

import java.io.FileReader;
import java.net.URI;
import java.util.LinkedHashMap;

import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.core.Base58;
import org.jose4j.base64url.internal.apache.commons.codec.binary.Base64;

import com.github.jsonldjava.utils.JsonUtils;

import fi.trustnet.verifiablecredentials.VerifiableCredential;
import info.weboftrust.ldsignatures.validator.Ed25519Signature2018LdValidator;
import uniresolver.client.ClientUniResolver;
import uniresolver.ddo.DDO;

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

		DDO ddo = clientUniResolver.resolve(issuer.toString());
		System.out.println(JsonUtils.toPrettyString(ddo.getJsonLdObject()));
		String issuerPublicKeyBase64 = ddo.getOwner().getPublicKeyBase64();
		issuerPublicKey = Base58.decode(issuerPublicKeyBase64);
		System.out.println("Issuer Public Key: " + Hex.encodeHexString(issuerPublicKey));

		// verify verifiable credential

		Ed25519Signature2018LdValidator validator = new Ed25519Signature2018LdValidator(issuerPublicKey);
		boolean validate = validator.validate(verifiableCredential.getJsonLdObject());

		// output

		System.out.println(validate);
	}
}
