package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * 役職コード一覧画面Dto
 *
 * @author axio
 */
@Setter
@Getter
public class AuthPosCodeListDto {

	/** 選択済みフラグ */
	private boolean selectedFlag;

	/** チェックフラグ */
	private boolean checkedFlag;

	/** 会社コード */
	private String companyCode;

	/** 役職コード */
	private String positionCode;

	/** 役職名称 */
	private String positionNameJp;

	/** 適用開始日(yyyy/MM/dd形式） */
	private String startDateYmd;

	/** 適用終了日(yyyy/MM/dd形式） */
	private String endDateYmd;
}