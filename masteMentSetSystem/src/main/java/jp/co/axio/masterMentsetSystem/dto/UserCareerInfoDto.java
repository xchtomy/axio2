package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * ユーザ詳細その他Dto
 *
 * @author axio
 */

@Setter
@Getter
public class UserCareerInfoDto {

	/** 部署名 */
	private String organizationNameJp;
	/** 有効開始日 */
	private String startDate;
	/** 有効終了日 */
	private String endDate;
	/** 役職 */
	private String positionNameJp;
}
