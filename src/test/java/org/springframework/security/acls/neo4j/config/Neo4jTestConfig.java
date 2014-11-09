package org.springframework.security.acls.neo4j.config;

import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.factory.GraphDatabaseSettings;
import org.neo4j.test.TestGraphDatabaseFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.data.neo4j.config.JtaTransactionManagerFactoryBean;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.neo4j.Neo4jLookupStrategy;
import org.springframework.security.acls.neo4j.Neo4jMutableAclService;
import org.springframework.transaction.PlatformTransactionManager;

@Configuration
@ComponentScan(basePackages = { "org.springframework.security.acls.neo4j" })
@Profile(value="dev-neo4j")
public class Neo4jTestConfig extends SpringSecurityNeo4jConfig {
	
	@Autowired
	private AclCache aclCache;
	
	@Autowired
	private AclAuthorizationStrategy aclAuthorizationStrategy;
	
	@Autowired
	private PermissionGrantingStrategy permissionGrantingStrategy;

	@Bean
	public LookupStrategy lookupStrategy() {
		return new Neo4jLookupStrategy(graphDatabaseService(), aclCache,
				aclAuthorizationStrategy, permissionGrantingStrategy);
	}

	@Bean
	public MutableAclService mutableAclService() {
		return new Neo4jMutableAclService(graphDatabaseService(), aclCache,
				lookupStrategy());
	}

	// @Bean
	// public GraphDatabaseService graphDatabaseService() {
	// return new GraphDatabaseFactory()
	// .newEmbeddedDatabase("target/spring-security-acl-neo4j-test");
	// }

	@Bean
	public GraphDatabaseService graphDatabaseService() {
		GraphDatabaseService db = new TestGraphDatabaseFactory()
				.newImpermanentDatabaseBuilder()
				.setConfig(GraphDatabaseSettings.nodestore_mapped_memory_size,
						"10M")
				.setConfig(GraphDatabaseSettings.string_block_size, "60")
				.setConfig(GraphDatabaseSettings.array_block_size, "300")
				.newGraphDatabase();
		return db;
	}

	@Bean
	public PlatformTransactionManager neo4jTransactionManager()
			throws Exception {
		JtaTransactionManagerFactoryBean jtaTransactionManagerFactoryBean = new JtaTransactionManagerFactoryBean(
				graphDatabaseService());
		return jtaTransactionManagerFactoryBean.getObject();
	}
}
