[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=alapierre_ksef-java-rest-client&metric=alert_status)](https://sonarcloud.io/dashboard?id=alapierre_gobl.java)
[![Renovate enabled](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)](https://renovatebot.com/)
[![Maven Central](http://img.shields.io/maven-central/v/io.alapierre.gobl/gobl-java)](https://search.maven.org/artifact/io.alapierre.gobl/gobl-java)

# GOBL Java implementation

## Early stage functionality

- parse Invoice from Json file
- make Invoice signature and save it as an Envelop
- save Invoice to file

## Current limitation

- The only possible type of document that can be placed inside a signed Envelope is an Invoice. This decision is dictated by the simplification of implementation at this stage of the project.
- There is no tax calculation logic
- No signature validation
- No JWK keys load functionality
- and much, much more — some help is more than welcome

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

### Create and Save Invoice

````java
Invoice invoice = new Invoice();

invoice.setCode("standard");
invoice.setIssueDate("2024-01-01");

Gobl gobl = new Gobl();

gobl.saveInvoice(invoice, System.out);
````

## Build requirements

The project can be built on JDK17+.

Building the API client library requires:
1. Java 17+
2. Maven
