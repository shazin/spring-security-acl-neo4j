package org.springframework.security.acls.neo4j.config;

import javax.sql.DataSource;

import net.sf.ehcache.store.AuthoritativeTier;

import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.factory.GraphDatabaseSettings;
import org.neo4j.test.TestGraphDatabaseFactory;
import org.springframework.cache.ehcache.EhCacheFactoryBean;
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.neo4j.config.JtaTransactionManagerFactoryBean;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.domain.AclAuthorizationStrategyImpl;
import org.springframework.security.acls.domain.ConsoleAuditLogger;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy;
import org.springframework.security.acls.domain.EhCacheBasedAclCache;
import org.springframework.security.acls.domain.PermissionFactory;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.security.acls.neo4j.Neo4jLookupStrategy;
import org.springframework.security.acls.neo4j.Neo4jMutableAclService;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.transaction.PlatformTransactionManager;

@Configuration
@ComponentScan(basePackages = { "org.springframework.security.acls.neo4j" })
public class AppTestConfig extends SpringSecurityNeo4jConfig {
	
//	@Bean 
//	public LookupStrategy lookupStrategy() {
//		return new BasicLookupStrategy(dataSource(), aclCache(), aclAuthorizationStrategy(), permissionGrantingStrategy());
//	}
//	
//	@Bean
//	public MutableAclService MutableAclService() {
//		return new JdbcMutableAclService(dataSource(), lookupStrategy(), aclCache());
//	}
	
	@Bean 
	public LookupStrategy lookupStrategy() {
		return new Neo4jLookupStrategy(graphDatabaseService(), aclCache(), aclAuthorizationStrategy(), permissionGrantingStrategy());	
	}
	
	@Bean
	public MutableAclService mutableAclService() {
		return new Neo4jMutableAclService(graphDatabaseService(), aclCache(), lookupStrategy());
	}
	
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2).addScript("META-INF/h2-security-acl-schema.sql").build();
	}
	
	@Bean
	public AclAuthorizationStrategy aclAuthorizationStrategy() {
		return new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"));
	}
	
	@Bean
	public PermissionGrantingStrategy permissionGrantingStrategy() {
		return new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger());
	}
	
	@Bean
	public PermissionFactory permissionFactory() {
		return new DefaultPermissionFactory();
	}
	
	@Bean
	public EhCacheBasedAclCache aclCache() {
		return new EhCacheBasedAclCache(ehCacheFactoryBean().getObject());
	}
	
	@Bean 
	public EhCacheFactoryBean ehCacheFactoryBean() {
		EhCacheFactoryBean ehCacheFactoryBean = new EhCacheFactoryBean();
		
		ehCacheFactoryBean.setCacheManager(new EhCacheManagerFactoryBean().getObject());
		ehCacheFactoryBean.setCacheName("aclCache");
		return ehCacheFactoryBean;
	}
	
//	@Bean
//	public GraphDatabaseService graphDatabaseService() {
//		return new GraphDatabaseFactory()
//				.newEmbeddedDatabase("target/spring-security-acl-neo4j-test");
//	}

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
