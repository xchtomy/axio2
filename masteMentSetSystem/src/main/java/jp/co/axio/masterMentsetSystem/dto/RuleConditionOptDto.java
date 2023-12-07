package jp.co.axio.masterMentsetSystem.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * 権限管理ルール条件セレクトDto
 *
 * @author JCBC
 */
@Setter
@Getter
public class RuleConditionOptDto {

	/*
	 * コンストラクタ
	 */
	public RuleConditionOptDto (String no, String kbn, String val) {
		super();
		optNo = no;
		optKbn = kbn;
		optValue = val;
	}

	/*
	 * コンストラクタ
	 */
	public RuleConditionOptDto () {
		super();
	}

	/** 条件番号 */
	public String optNo;

	/** 条件区分　　 0:付与、1:徐外*/
	public String optKbn;

	/** 条件値 */
	public String optValue;

}
