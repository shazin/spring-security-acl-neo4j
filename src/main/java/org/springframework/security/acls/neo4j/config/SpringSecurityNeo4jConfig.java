package org.springframework.security.acls.neo4j.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.neo4j.config.Neo4jConfiguration;

/**
 * Spring Security Neo4j Configuration
 * 
 * @author shazin
 *
 */
@Configuration
public class SpringSecurityNeo4jConfig extends Neo4jConfiguration {

	public SpringSecurityNeo4jConfig() {
		setBasePackage("org.springframework.security.acls.neo4j.model");
	}
	
	
}
