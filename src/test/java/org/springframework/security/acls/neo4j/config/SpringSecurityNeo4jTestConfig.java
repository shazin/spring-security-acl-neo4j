package org.springframework.security.acls.neo4j.config;

import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.factory.GraphDatabaseFactory;
import org.neo4j.graphdb.factory.GraphDatabaseSettings;
import org.neo4j.test.TestGraphDatabaseFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.neo4j.config.JtaTransactionManagerFactoryBean;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.transaction.PlatformTransactionManager;

@Configuration
public class SpringSecurityNeo4jTestConfig extends SpringSecurityNeo4jConfig {

	// @Bean
	// public GraphDatabaseService graphDatabaseService() {
	// GraphDatabaseService db = new TestGraphDatabaseFactory()
	// .newImpermanentDatabaseBuilder()
	// .setConfig(GraphDatabaseSettings.nodestore_mapped_memory_size,
	// "10M")
	// .setConfig(GraphDatabaseSettings.string_block_size, "60")
	// .setConfig(GraphDatabaseSettings.array_block_size, "300")
	// .newGraphDatabase();
	// return db;
	// }

	@Bean
	public GraphDatabaseService graphDatabaseService() {
		return new GraphDatabaseFactory()
				.newEmbeddedDatabase("target/spring-security-acl-neo4j-test");
	}

	@Bean
	public PlatformTransactionManager neo4jTransactionManager()
			throws Exception {
		JtaTransactionManagerFactoryBean jtaTransactionManagerFactoryBean = new JtaTransactionManagerFactoryBean(
				graphDatabaseService());
		return jtaTransactionManagerFactoryBean.getObject();
	}
}
