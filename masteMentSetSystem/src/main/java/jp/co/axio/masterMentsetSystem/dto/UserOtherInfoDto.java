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
public class UserOtherInfoDto {

	/** 項目名 */
	private String columnName;
	/** 項目値 */
	private String valueValue;

}
