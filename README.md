[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=alapierre_ksef-java-rest-client&metric=alert_status)](https://sonarcloud.io/dashboard?id=alapierre_gobl.java)
[![Renovate enabled](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)](https://renovatebot.com/)
[![Maven Central](http://img.shields.io/maven-central/v/io.alapierre.gobl/gobl-java)](https://search.maven.org/artifact/io.alapierre.gobl/gobl-java)

# GOBL Java implementation

## Early stage functionality

- parse `Invoice` from Json file
- make `Invoice` signature and save it as an `Envelop`
- save `Invoice` to file
- load and save JWK keys from/to file
- `Invoice` extract from `Envelop`
- signature verification when extract document from `Envelop` (only one signature is supported now)

## Current limitation

- The only possible type of document that can be placed inside a signed Envelope is an Invoice. This decision is dictated by the simplification of implementation at this stage of the project.
- There is no tax calculation logic
- and much, much more — so help is more than welcome

### Parse Invoice

````java
public class Main {
    public static void main(String[] args) {
        Gobl gobl = new Gobl();
        Invoice invoice = gobl.parseInvoice("src/test/resources/invoice.json");
        System.out.println(invoice);
    }
}
````

### Sign Invoice file

````java
public class Main {

    public static void main(String[] args) {
        Gobl gobl = new Gobl();

        KeySupport keySupport = new KeySupport();
        val keys = keySupport.generate();

        val envelope = gobl.signInvoice("src/test/resources/invoice.json", keys.privateKey(), UUID.randomUUID());
        System.out.println(envelope);
    }
    
}
````

### Sign Invoice with key from file

````java
public class Main {

    public static void main(String[] args) {
        Gobl gobl = new Gobl();

        KeySupport keySupport = new KeySupport();
        Key key = keySupport.loadKey(Path.of("src/test/resources/id_es256.jwk"));

        val envelope = gobl.signInvoice("src/test/resources/invoice.json", (ECPrivateKey) key, UUID.randomUUID());
        System.out.println(envelope);
    }
    
}
````

### Check signature and extract `Invoice` from `Envelope`

````java
try{
    File file = new File("src/test/resources/invoice-signed.json");
    KeySupport keySupport = new KeySupport();
    Key publicKey = keySupport.loadKey(Path.of("src/test/resources/id_es256.pub.jwk"));
    
    Invoice invoice = gobl.extractFromEnvelope(file, Invoice.class, publicKey); 
    // validation OK
    System.out.println(invoice);
    } catch (SignatureException ex) {
        // validation failed
    }   
````

### Create and Save Invoice

````java
val invoice = new Invoice()
        .withCode("standard")
        .withIssueDate("2024-01-01")
        .withCustomer(new Party()
                .withName("Company INC")
                .withAddresses(List.of(new Address()
                        .withCountry("Poland")
                        .withCode("05-092")
                        .withStreet("Warszawska")))
                .withTaxId(new Identity()
                        .withCode("2222222222")
                        .withCountry("PL"))
        ).withCustomer(new Party()
                .withName("Customer sp. z o.o.")
                .withAddresses(List.of(new Address()
                        .withCountry("Poland")
                        .withCode("05-092")
                        .withStreet("Warszawska")))
                .withTaxId(new Identity()
                        .withCode("1111111111")
                        .withCountry("PL"))
        ).withLines(List.of(new Line()
                .withI(1)
                .withItem(new Item()
                        .withName("Myszka")
                        .withCurrency("PLN")
                        .withPrice("100"))));

Gobl gobl = new Gobl();
gobl.saveInvoice(invoice, System.out);
````

## Maven dependency

````xml
<dependency>
    <groupId>io.alapierre.gobl</groupId>
    <artifactId>gobl-core</artifactId>
    <version>0.0.2</version>
</dependency>
````

## Build requirements

The project can be built on JDK17+.

Building the API client library requires:
1. Java 17+
2. Maven
