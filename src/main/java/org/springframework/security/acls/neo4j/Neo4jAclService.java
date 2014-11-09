package org.springframework.security.acls.neo4j;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.neo4j.graphdb.GraphDatabaseService;
import org.springframework.data.neo4j.conversion.Result;
import org.springframework.data.neo4j.support.Neo4jTemplate;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.util.Assert;

public class Neo4jAclService implements AclService {

	protected LookupStrategy lookupStrategy;
	protected AclCache aclCache;
	protected Neo4jTemplate neo4jTemplate;
	
	private final String DEFAULT_FIND_CHILDREN = "MATCH (acl:AclNode)-[:SECURES]->(class:ClassNode) OPTIONAL MATCH (parentAcl:AclNode)-[:SECURES]->(parentClass:ClassNode) WITH parentAcl, parentClass, acl, class WHERE acl.parentObject = parentAcl.id AND parentAcl.objectIdIdentity = {objectIdIdentity} AND parentClass.className = {className} RETURN acl.objectIdIdentity AS aclId, class.className AS className";
	private String findChildrenSql = DEFAULT_FIND_CHILDREN;

	public Neo4jAclService(GraphDatabaseService graphDatabaseService,
			LookupStrategy lookupStrategy, AclCache aclCache) {
		Assert.notNull(aclCache, "AclCache can not be null");
		Assert.notNull(lookupStrategy, "LookStrategy can not be null");
		Assert.notNull(graphDatabaseService,
				"GraphDatabaseService can not be null");
		this.neo4jTemplate = new Neo4jTemplate(graphDatabaseService);
		this.lookupStrategy = lookupStrategy;
		this.aclCache = aclCache;
	}

	@Override
	public List<ObjectIdentity> findChildren(ObjectIdentity parentIdentity) {
		List<ObjectIdentity> objects = new ArrayList<ObjectIdentity>();
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("objectIdIdentity", (Long) parentIdentity.getIdentifier());
		params.put("className", parentIdentity.getType());
		Result<Map<String, Object>> result = neo4jTemplate.query(
				findChildrenSql, params);
		Iterator<Map<String, Object>> it = result.iterator();
		Map<String, Object> data = null;
		while (it.hasNext()) {
			data = it.next();
			objects.add(new ObjectIdentityImpl((String) data.get("className"),
					(Long) data.get("aclId")));
		}

		return objects;
	}

	@Override
	public Acl readAclById(ObjectIdentity object) throws NotFoundException {
		return readAclById(object, null);
	}

	@Override
	public Acl readAclById(ObjectIdentity object, List<Sid> sids)
			throws NotFoundException {
		Map<ObjectIdentity, Acl> map = readAclsById(Arrays.asList(object), sids);
		Assert.isTrue(map.containsKey(object),
				"There should have been an Acl entry for ObjectIdentity "
						+ object);

		return (Acl) map.get(object);
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects,
			List<Sid> sids) throws NotFoundException {
		Map<ObjectIdentity, Acl> result = lookupStrategy.readAclsById(objects,
				sids);

		// Check every requested object identity was found (throw
		// NotFoundException if needed)
		for (ObjectIdentity oid : objects) {
			if (!result.containsKey(oid)) {
				throw new NotFoundException(
						"Unable to find ACL information for object identity '"
								+ oid + "'");
			}
		}

		return result;
	}

	@Override
	public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects)
			throws NotFoundException {
		return readAclsById(objects, null);
	}

	public LookupStrategy getLookupStrategy() {
		return lookupStrategy;
	}

	public void setLookupStrategy(LookupStrategy lookupStrategy) {
		this.lookupStrategy = lookupStrategy;
	}

	public AclCache getAclCache() {
		return aclCache;
	}

	public void setAclCache(AclCache aclCache) {
		this.aclCache = aclCache;
	}

	public Neo4jTemplate getNeo4jTemplate() {
		return neo4jTemplate;
	}

	public void setNeo4jTemplate(Neo4jTemplate neo4jTemplate) {
		this.neo4jTemplate = neo4jTemplate;
	}

	public String getFindChildrenSql() {
		return findChildrenSql;
	}

	public void setFindChildrenSql(String findChildrenSql) {
		this.findChildrenSql = findChildrenSql;
	}

}
