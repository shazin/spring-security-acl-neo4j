package org.springframework.security.acls.neo4j.model;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.neo4j.graphdb.Direction;
import org.springframework.data.neo4j.annotation.Fetch;
import org.springframework.data.neo4j.annotation.GraphId;
import org.springframework.data.neo4j.annotation.Indexed;
import org.springframework.data.neo4j.annotation.NodeEntity;
import org.springframework.data.neo4j.annotation.RelatedTo;
import org.springframework.data.neo4j.support.index.IndexType;

/**
 * Acl Node to represent Object Identity
 * 
 * @author shazin
 *
 */
@NodeEntity
public class AclNode extends BaseNode {

	// Graph Identifier
	@GraphId
	private Long graphId;

	// Entries Inheriting
	private Boolean entriesInheriting;

	// Object Id Identity
	@Indexed(indexName = "object_id_identity", indexType = IndexType.FULLTEXT)
	private Long objectIdIdentity;

	// Parent Object
	@Indexed(indexName = "parent_object", indexType = IndexType.FULLTEXT)
	private String parentObject;

	// Securing Class Node
	@RelatedTo(type = "SECURES", direction = Direction.OUTGOING)
	private ClassNode classNode;

	// Owning Sid
	@RelatedTo(type = "OWNED_BY", direction = Direction.OUTGOING)
	private SidNode ownerSid;

	// Aces which composes this Acl
	@RelatedTo(type = "COMPOSES", direction = Direction.INCOMING)
	@Fetch
	private Set<AceNode> aces = new HashSet<AceNode>();

	/**
	 * Default Constructor
	 */
	public AclNode() {
	}
	
	/**
	 * Conversion Constructor
	 * 
	 * @param entriesInheriting - Entries Inheriting Flag
	 * @param objectIdIdentity - Object Id Identity
	 * @param parentObject - Parent Object
	 * @param classNode - Class Node
	 * @param ownerSid - Owner Sid
	 */
	public AclNode(Boolean entriesInheriting, Long objectIdIdentity,
			String parentObject, ClassNode classNode, SidNode ownerSid) {
		this();
		this.entriesInheriting = entriesInheriting;
		this.objectIdIdentity = objectIdIdentity;
		this.parentObject = parentObject;
		this.classNode = classNode;
		this.ownerSid = ownerSid;
	}

	public Boolean getEntriesInheriting() {
		return entriesInheriting;
	}

	public void setEntriesInheriting(Boolean entriesInheriting) {
		this.entriesInheriting = entriesInheriting;
	}

	public Long getObjectIdIdentity() {
		return objectIdIdentity;
	}

	public void setObjectIdIdentity(Long objectIdIdentity) {
		this.objectIdIdentity = objectIdIdentity;
	}

	public String getParentObject() {
		return parentObject;
	}

	public void setParentObject(String parentObject) {
		this.parentObject = parentObject;
	}

	public ClassNode getClassNode() {
		return classNode;
	}

	public void setClassNode(ClassNode classNode) {
		this.classNode = classNode;
	}

	public SidNode getOwnerSid() {
		return ownerSid;
	}

	public void setOwnerSid(SidNode ownerSid) {
		this.ownerSid = ownerSid;
	}

	public Set<AceNode> getAces() {
		return aces;
	}

	public void setAces(Set<AceNode> aces) {
		this.aces = aces;
	}

	public Long getGraphId() {
		return graphId;
	}

	public void setGraphId(Long graphId) {
		this.graphId = graphId;
	}

	public boolean equals(Object o) {
		if (o == null) {
			return false;
		}

		if (o == this) {
			return true;
		}

		if (o instanceof AclNode) {
			AclNode other = (AclNode) o;
			return Objects.equals(getObjectIdIdentity(),
					other.getObjectIdIdentity())
					&& Objects.equals(getEntriesInheriting(),
							other.getEntriesInheriting())
					&& Objects.equals(getParentObject(),
							other.getParentObject())
					&& Objects.equals(getClassNode(), other.getClassNode())
					&& Objects.equals(getOwnerSid(), other.getOwnerSid());
		}

		return false;
	}

	public int hashCode() {
		return Objects.hash(getObjectIdIdentity(), getEntriesInheriting(),
				getParentObject(), getClassNode(), getOwnerSid());
	}

	public String toString() {
		return "AclNode[id=" + getId() + ", objectIdIdentity="
				+ getObjectIdIdentity() + ", entriesInheriting="
				+ getEntriesInheriting() + ", parentObject="
				+ getParentObject() + ", class=" + getClassNode() + "]";
	}

}
