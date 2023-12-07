package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * ユーザーID一覧画面Dto
 *
 * @author axio
 */
@Setter
@Getter
public class AuthUserCodeListDto {

	/** 選択済みフラグ */
	private boolean selectedFlag;

	/** チェックフラグ */
	private boolean checkedFlag;

	/** ユーザーID */
	private String userCode;

	/** ユーザー氏名 */
	private String userNameJp;

	/** 所属部署 */
	private String departmentName;

	/** 開始日(yyyy/MM/dd形式） */
	private String startDateYmd;

	/** 終了日(yyyy/MM/dd形式） */
	private String endDateYmd;
}