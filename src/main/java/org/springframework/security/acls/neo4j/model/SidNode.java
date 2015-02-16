package org.springframework.security.acls.neo4j.model;

import java.util.Objects;

import org.springframework.data.neo4j.annotation.GraphId;
import org.springframework.data.neo4j.annotation.Indexed;
import org.springframework.data.neo4j.annotation.NodeEntity;
import org.springframework.data.neo4j.support.index.IndexType;

/**
 * Sid Node representing Sid
 * 
 * @author shazin
 *
 */
@NodeEntity
public class SidNode extends BaseNode {

	// Graph Identifier
	@GraphId
	private Long graphId;

	// Principal Flag
	@Indexed(indexName = "principal", indexType = IndexType.FULLTEXT)
	private Boolean principal = false;

	// Sid
	@Indexed(indexName = "sid", indexType = IndexType.FULLTEXT)
	private String sid;

	/**
	 * Default Constructor
	 */
	public SidNode() {
	}

	/**
	 * Conversion Constructor
	 * 
	 * @param sid - Sid
	 * @param principal - Principal Flag
	 */
	public SidNode(String sid, Boolean principal) {
		this();
		this.principal = principal;
		this.sid = sid;
	}

	public Long getGraphId() {
		return graphId;
	}

	public void setGraphId(Long graphId) {
		this.graphId = graphId;
	}

	public Boolean getPrincipal() {
		return principal;
	}

	public void setPrincipal(Boolean principal) {
		this.principal = principal;
	}

	public String getSid() {
		return sid;
	}

	public void setSid(String sid) {
		this.sid = sid;
	}

	public boolean equals(Object o) {
		if (o == null) {
			return false;
		}

		if (o == this) {
			return true;
		}

		if (o instanceof SidNode) {
			SidNode other = (SidNode) o;
			return Objects.equals(getSid(), other.getSid())
					&& Objects.equals(getPrincipal(), other.getPrincipal());
		}

		return false;
	}

	public int hashCode() {
		return Objects.hash(getSid(), getPrincipal());
	}

	public String toString() {
		return "SidNode[id=" + getId() + ", principal=" + getPrincipal() + "]";
	}
}
