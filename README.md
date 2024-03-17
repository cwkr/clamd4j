# clamd4j [![Coverage Status](https://coveralls.io/repos/github/cwkr/clamd4j/badge.svg?branch=main)](https://coveralls.io/github/cwkr/clamd4j?branch=main) [![Javadocs](https://www.javadoc.io/badge/de.cwkr/clamd4j.svg?color=blue)](https://www.javadoc.io/doc/de.cwkr/clamd4j)

ClamAV Daemon Client for Java

## Installation

Add the following dependency to the `<dependencies>` section of your `pom.xml` file when using [Maven](https://maven.apache.org/).

```xml
<dependency>
    <groupId>de.cwkr</groupId>
    <artifactId>clamd4j</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

```java
import de.cwkr.clamd4j.ClamdClient;
import de.cwkr.clamd4j.SuspiciousFile;
import java.util.Collections;

void main() {
    var clamdClient = new ClamdClient();
    var suspiciousFile = SuspiciousFile.of(new byte[]{});
    var report = clamdClient.scan(Collections.singletonList(suspiciousFile));
}
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](LICENSE)
