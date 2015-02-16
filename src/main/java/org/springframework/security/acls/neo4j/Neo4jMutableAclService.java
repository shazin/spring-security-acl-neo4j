package org.springframework.security.acls.neo4j;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.neo4j.graphdb.GraphDatabaseService;
import org.springframework.dao.DataAccessException;
import org.springframework.data.neo4j.conversion.Result;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.ChildrenExistException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.neo4j.model.AceNode;
import org.springframework.security.acls.neo4j.model.AclNode;
import org.springframework.security.acls.neo4j.model.ClassNode;
import org.springframework.security.acls.neo4j.model.SidNode;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.Assert;

/**
 * Neo4j based Mutable Acl Service Implementation
 * 
 * @author shazin
 *
 */
@Transactional(readOnly = true)
public class Neo4jMutableAclService extends Neo4jAclService implements
		MutableAclService {

	private String selectObjectIdentity = "MATCH (class:ClassNode)<-[:SECURES]-(acl:AclNode) WHERE acl.objectIdIdentity = {objectIdIdentity} AND class.className = {className} RETURN acl";
	private String selectSid = "MATCH (sid:SidNode) WHERE sid.sid = {sid} AND sid.principal = {principal} RETURN sid";
	private String selectClass = "MATCH (class:ClassNode) WHERE class.className = {className} RETURN class";
	private String deleteEntryByObjectIdentityId = "MATCH (acl:AclNode) OPTIONAL MATCH (acl)<-[c:COMPOSES]-(ace:AceNode)-[a:AUTHORIZES]->(sid:SidNode) WHERE acl.id = {aclId} DELETE c, a, ace";
	private String deleteObjectIdentityByObjectIdentityId = "MATCH (owner:SidNode)<-[o:OWNED_BY]-(acl:AclNode)-[s:SECURES]->(class:ClassNode) WHERE acl.id = {aclId} DELETE s, o, acl";

	/**
	 * Constructor
	 * 
	 * @param graphDatabaseService - Graph Database Service
	 * @param aclCache - Acl Cache
	 * @param lookupStrategy - Lookup Strategy
	 */
	public Neo4jMutableAclService(GraphDatabaseService graphDatabaseService,
			AclCache aclCache, LookupStrategy lookupStrategy) {
		super(graphDatabaseService, lookupStrategy, aclCache);
	}

	/**
	 * Create Acl
	 */
	@Override
	@Transactional(rollbackFor = Exception.class)
	public MutableAcl createAcl(ObjectIdentity objectIdentity)
			throws AlreadyExistsException {
		Assert.notNull(objectIdentity, "Object Identity required");

		// Check this object identity hasn't already been persisted
		if (retrieveObjectIdentityId(objectIdentity) != null) {
			throw new AlreadyExistsException("Object identity '"
					+ objectIdentity + "' already exists");
		}

		// Need to retrieve the current principal, in order to know who "owns"
		// this ACL (can be changed later on)
		Authentication auth = SecurityContextHolder.getContext()
				.getAuthentication();
		PrincipalSid sid = new PrincipalSid(auth);

		// Create the acl_object_identity row
		createObjectIdentity(objectIdentity, sid);

		// Retrieve the ACL via superclass (ensures cache registration, proper
		// retrieval etc)
		Acl acl = readAclById(objectIdentity);
		Assert.isInstanceOf(MutableAcl.class, acl,
				"MutableAcl should be been returned");

		return (MutableAcl) acl;
	}

	/**
	 * Delete Acl
	 */
	@Override
	@Transactional(rollbackFor = Exception.class)
	public void deleteAcl(ObjectIdentity objectIdentity, boolean deleteChildren)
			throws ChildrenExistException {
		Assert.notNull(objectIdentity, "Object Identity required");
		Assert.notNull(objectIdentity.getIdentifier(),
				"Object Identity doesn't provide an identifier");

		if (deleteChildren) {
			List<ObjectIdentity> children = findChildren(objectIdentity);
			if (children != null) {
				for (ObjectIdentity child : children) {
					deleteAcl(child, true);
				}
			}
		}

		String oidPrimaryKey = retrieveObjectIdentityId(objectIdentity);

		// Delete this ACL's ACEs in the acl_entry table
		deleteEntries(oidPrimaryKey);

		// Delete this ACL's acl_object_identity row
		deleteObjectIdentity(oidPrimaryKey);

		// Clear the cache
		aclCache.evictFromCache(objectIdentity);
	}

	/**
	 * Update Acl
	 */
	@Override
	@Transactional(rollbackFor = Exception.class)
	public MutableAcl updateAcl(MutableAcl acl) throws NotFoundException {
		Assert.notNull(acl.getId(),
				"Object Identity doesn't provide an identifier");

		// Delete this ACL's ACEs in the acl_entry table
		deleteEntries(retrieveObjectIdentityId(acl.getObjectIdentity()));

		// Create this ACL's ACEs in the acl_entry table
		createEntries(acl);

		// Change the mutable columns in acl_object_identity
		updateObjectIdentity(acl);

		// Clear the cache, including children
		clearCacheIncludingChildren(acl.getObjectIdentity());

		// Retrieve the ACL via superclass (ensures cache registration, proper
		// retrieval etc)
		return (MutableAcl) super.readAclById(acl.getObjectIdentity());
	}

	/**
	 * Retrieve Object Identity Id
	 * 
	 * @param oid - Object Identity
	 * @return Id
	 */
	protected String retrieveObjectIdentityId(ObjectIdentity oid) {
		try {
			AclNode acl = retrieveAclNode(oid);
			if (acl == null) {
				return null;
			} else {
				return acl.getId();
			}
		} catch (DataAccessException notFound) {
			return null;
		}
	}

	/**
	 * Retrieve Acl Node
	 * 
	 * @param oid - Object Identity
	 * @return Acl Node
	 */
	private AclNode retrieveAclNode(ObjectIdentity oid) {
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("objectIdIdentity", (Long) oid.getIdentifier());
		params.put("className", oid.getType());
		Result<Map<String, Object>> result = neo4jTemplate.query(
				selectObjectIdentity, params);
		Result<AclNode> aclNode = result.to(AclNode.class);
		AclNode acl = aclNode.singleOrNull();
		return acl;
	}

	/**
	 * Create Object Identity
	 * 
	 * @param object - Object Identity
	 * @param owner - Owner Sid
	 */
	protected void createObjectIdentity(ObjectIdentity object, Sid owner) {
		Assert.isTrue(
				TransactionSynchronizationManager.isSynchronizationActive(),
				"Transaction must be running");
		SidNode sid = createOrRetrieveSid(owner, true);
		ClassNode classNode = createOrRetrieveClass(object.getType(), true);
		AclNode aclNode = new AclNode(Boolean.TRUE,
				(Long) object.getIdentifier(), null, classNode, sid);
		AclNode savedAcl = neo4jTemplate.save(aclNode);
	}

	/**
	 * Create or Retrieve Sid
	 * 
	 * @param sid - Sid
	 * @param allowCreate - Allow Create Flag
	 * @return Sid Node
	 */
	protected SidNode createOrRetrieveSid(Sid sid, boolean allowCreate) {
		Assert.notNull(sid, "Sid required");

		String sidName;
		boolean sidIsPrincipal = true;

		if (sid instanceof PrincipalSid) {
			sidName = ((PrincipalSid) sid).getPrincipal();
		} else if (sid instanceof GrantedAuthoritySid) {
			sidName = ((GrantedAuthoritySid) sid).getGrantedAuthority();
			sidIsPrincipal = false;
		} else {
			throw new IllegalArgumentException(
					"Unsupported implementation of Sid");
		}

		Map<String, Object> params = new HashMap<String, Object>();
		params.put("sid", sidName);
		params.put("principal", sidIsPrincipal);
		Result<Map<String, Object>> result = neo4jTemplate.query(selectSid,
				params);
		Result<SidNode> sidNode = result.to(SidNode.class);

		if (sidNode.iterator().hasNext()) {
			return sidNode.iterator().next();
		}

		if (allowCreate) {
			SidNode newSid = new SidNode(sidName, sidIsPrincipal);
			SidNode savedSid = neo4jTemplate.save(newSid);
			return savedSid;
		}

		return null;
	}

	/**
	 * Create of Retrieve Class
	 * 
	 * @param type - Class Type
	 * @param allowCreate - Allow Create Flag
	 * @return Class Node
	 */
	protected ClassNode createOrRetrieveClass(String type, boolean allowCreate) {
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("className", type);
		Result<Map<String, Object>> result = neo4jTemplate.query(selectClass,
				params);
		Result<ClassNode> classNode = result.to(ClassNode.class);

		if (classNode.iterator().hasNext()) {
			return classNode.iterator().next();
		}

		if (allowCreate) {
			ClassNode newClassNode = new ClassNode(type);
			ClassNode savedClassNode = neo4jTemplate.save(newClassNode);
			return savedClassNode;
		}

		return null;
	}

	/**
	 * Delete Entries by Object Identity Id
	 * 
	 * @param objectIdentityId
	 */
	protected void deleteEntries(String objectIdentityId) {
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("aclId", objectIdentityId);
		neo4jTemplate.query(deleteEntryByObjectIdentityId, params);
	}

	/**
	 * Delete Object Identity by Object Identity Id
	 * 
	 * @param objectIdentityId
	 */
	protected void deleteObjectIdentity(String objectIdentityId) {
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("aclId", objectIdentityId);
		neo4jTemplate.query(deleteObjectIdentityByObjectIdentityId, params);
	}

	/**
	 * Create Entries for Acl
	 * 
	 * @param acl
	 */
	protected void createEntries(final MutableAcl acl) {
		if (acl.getEntries().isEmpty()) {
			return;
		}
		AclNode aclNode = retrieveAclNode(acl.getObjectIdentity());
		if (aclNode == null) {
			return;
		}
		Set<AceNode> aces = new HashSet<AceNode>();
		int i = aclNode.getAces().size();
		for (AccessControlEntry ace : acl.getEntries()) {
			AccessControlEntryImpl entry = (AccessControlEntryImpl) ace;
			aces.add(neo4jTemplate.save(new AceNode(createOrRetrieveSid(
					entry.getSid(), true), i, entry.getPermission().getMask(),
					entry.isGranting(), entry.isAuditSuccess(), entry
							.isAuditFailure())));
			i++;
		}
		aclNode.setAces(aces);
		AclNode savedAclNode = neo4jTemplate.save(aclNode);
	}

	/**
	 * Update Object Identity
	 * 
	 * @param acl
	 */
	protected void updateObjectIdentity(MutableAcl acl) {
		String parentId = null;

		if (acl.getParentAcl() != null) {
			Assert.isInstanceOf(ObjectIdentityImpl.class, acl.getParentAcl()
					.getObjectIdentity(),
					"Implementation only supports ObjectIdentityImpl");

			ObjectIdentityImpl oii = (ObjectIdentityImpl) acl.getParentAcl()
					.getObjectIdentity();
			parentId = retrieveObjectIdentityId(oii);
		}

		Assert.notNull(acl.getOwner(),
				"Owner is required in this implementation");

		SidNode ownerSid = createOrRetrieveSid(acl.getOwner(), true);
		AclNode aclNode = retrieveAclNode(acl.getObjectIdentity());

		if (aclNode == null) {
			throw new NotFoundException("Unable to locate ACL to update");
		}

		aclNode.setOwnerSid(ownerSid);
		aclNode.setParentObject(parentId);
		aclNode.setEntriesInheriting(acl.isEntriesInheriting());

		neo4jTemplate.save(aclNode);
	}

	/**
	 * Clear Cache including Children
	 * 
	 * @param objectIdentity
	 */
	private void clearCacheIncludingChildren(ObjectIdentity objectIdentity) {
		Assert.notNull(objectIdentity, "ObjectIdentity required");
		List<ObjectIdentity> children = findChildren(objectIdentity);
		if (children != null) {
			for (ObjectIdentity child : children) {
				clearCacheIncludingChildren(child);
			}
		}
		aclCache.evictFromCache(objectIdentity);
	}

	/**
	 * Get Select Object Identity Cypher
	 * 
	 * @return selectObjectIdentity
	 */
	public String getSelectObjectIdentity() {
		return selectObjectIdentity;
	}

	/**
	 * Set Select Object Identity Cypher
	 * 
	 * @param selectObjectIdentity
	 */
	public void setSelectObjectIdentity(String selectObjectIdentity) {
		this.selectObjectIdentity = selectObjectIdentity;
	}

	/**
	 * Get Select Sid Cypher
	 * 
	 * @return selectSid
	 */
	public String getSelectSid() {
		return selectSid;
	}

	/**
	 * Set Select Sid Cypher
	 * 
	 * @param selectSid
	 */
	public void setSelectSid(String selectSid) {
		this.selectSid = selectSid;
	}

	/**
	 * Get Select Class Cypher
	 * 
	 * @return selectClass
	 */
	public String getSelectClass() {
		return selectClass;
	}

	/**
	 * Set Select Class Cypher
	 * 
	 * @param selectClass
	 */
	public void setSelectClass(String selectClass) {
		this.selectClass = selectClass;
	}

	/**
	 * Get Delete Object Entry By Object Identity Id Cypher
	 * 
	 * @return deleteEntryByObjectIdentityId
	 */
	public String getDeleteEntryByObjectIdentityId() {
		return deleteEntryByObjectIdentityId;
	}

	/**
	 * Set Delete Object Entry By Object Identity Id Cypher
	 * 
	 * @param deleteEntryByObjectIdentityId
	 */
	public void setDeleteEntryByObjectIdentityId(
			String deleteEntryByObjectIdentityId) {
		this.deleteEntryByObjectIdentityId = deleteEntryByObjectIdentityId;
	}

	/**
	 * Get Delete Object Identity By Object Identity Id
	 * 
	 * @return deleteObjectIdentityByObjectIdentityId
	 */
	public String getDeleteObjectIdentityByObjectIdentityId() {
		return deleteObjectIdentityByObjectIdentityId;
	}

	/**
	 * Set Delete Object Identity By Object Identity Id
	 * 
	 * @param deleteObjectIdentityByObjectIdentityId
	 */
	public void setDeleteObjectIdentityByObjectIdentityId(
			String deleteObjectIdentityByObjectIdentityId) {
		this.deleteObjectIdentityByObjectIdentityId = deleteObjectIdentityByObjectIdentityId;
	}

}
