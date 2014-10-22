package org.springframework.security.acls.neo4j.config;

import org.springframework.cache.ehcache.EhCacheFactoryBean;
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.acls.domain.DefaultPermissionFactory;
import org.springframework.security.acls.domain.EhCacheBasedAclCache;
import org.springframework.security.acls.domain.PermissionFactory;

@Configuration
public class SpringSecurityAclTestConfig {

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

	/*
	<bean id="lookupStrategy"
		class="org.springframework.security.acls.jpa.JpaNativeQueryLookupStrategy">
		<constructor-arg ref="aclCache" />
		<constructor-arg>
			<!-- Need to create a custom strategy as the default impl doesn't allows 
				multiple roles for the following special permissions: 1. Change ownership 
				2. Modify auditing details 3. change ACL and ACE details MyResult contains 
				5 admin roles to create ACL and ACE details in user registration and edit 
				user functions -->
			<bean class="my.mimos.mrf.domain.acls.MrfAclAuthorizationStrategy">
				<constructor-arg>
					<list>
						<list>
							<bean
								class="org.springframework.security.core.authority.SimpleGrantedAuthority">
								<constructor-arg>
									<util:constant
										static-field="my.mimos.mrf.constant.CommonConstant.ACL_SID_ROLE_SUPER_ADMIN" />
								</constructor-arg>
							</bean>
							<bean
								class="org.springframework.security.core.authority.SimpleGrantedAuthority">
								<constructor-arg>
									<util:constant
										static-field="my.mimos.mrf.constant.CommonConstant.ACL_SID_ROLE_MINISTRY_ADMIN" />
								</constructor-arg>
							</bean>
							<bean
								class="org.springframework.security.core.authority.SimpleGrantedAuthority">
								<constructor-arg>
									<util:constant
										static-field="my.mimos.mrf.constant.CommonConstant.ACL_SID_ROLE_EPU_BRO_ADMIN" />
								</constructor-arg>
							</bean>
							<bean
								class="org.springframework.security.core.authority.SimpleGrantedAuthority">
								<constructor-arg>
									<util:constant
										static-field="my.mimos.mrf.constant.CommonConstant.ACL_SID_ROLE_JPA_BRO_ADMIN" />
								</constructor-arg>
							</bean>
							<bean
								class="org.springframework.security.core.authority.SimpleGrantedAuthority">
								<constructor-arg>
									<util:constant
										static-field="my.mimos.mrf.constant.CommonConstant.ACL_SID_ROLE_MOF_BRO_ADMIN" />
								</constructor-arg>
							</bean>
						</list>
					</list>
				</constructor-arg>
			</bean>
		</constructor-arg>
		<constructor-arg>
			<bean
				class="org.springframework.security.acls.domain.DefaultPermissionGrantingStrategy">
				<constructor-arg>
					<bean class="org.springframework.security.acls.domain.ConsoleAuditLogger" />
				</constructor-arg>
			</bean>
		</constructor-arg>
		<property name="permissionFactory" ref="permissionFactory" />
	</bean>

	<bean id="aclService"
		class="org.springframework.security.acls.jpa.JpaMutableAclService">
		<constructor-arg ref="lookupStrategy" />
		<constructor-arg ref="aclCache" />
	</bean>

	<!-- to evaluate Spring security expression -->
	<bean id="expressionHandler"
		class="org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler">
		<property name="permissionEvaluator" ref="permissionEvaluator" />
		<property name="permissionCacheOptimizer">
			<bean class="org.springframework.security.acls.AclPermissionCacheOptimizer">
				<constructor-arg ref="aclService" />
			</bean>
		</property>
	</bean>

	<bean id="permissionEvaluator" class="my.mimos.mrf.domain.acls.MrfAclPermissionEvaluator">
		<constructor-arg ref="aclService" />
		<constructor-arg ref="aclGrantedAuthorityPolicyRepo" />
		<property name="permissionFactory" ref="permissionFactory" />
	</bean>
	 */
}
