package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * ユーザシステムDto
 *
 * @author axio
 */

@Setter
@Getter
public class UserManCmbOrgDto {

	/** 会社コード */
	private String companyCode;
	/** 部署コード */
	private String organizationCode;
	/** 部署名 */
	private String organizationNameJp;
	/** 役職コード */
	private String positionCode;
	/** 役職 */
	private String positionNameJp;

}
