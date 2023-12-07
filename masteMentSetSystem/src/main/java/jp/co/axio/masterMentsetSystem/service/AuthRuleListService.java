package jp.co.axio.masterMentsetSystem.service;

import java.text.SimpleDateFormat;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.AuthRuleListForm;
import jp.co.axio.masterMentsetSystem.dto.RuleConditionSetDto;
import jp.co.axio.masterMentsetSystem.model.MRuleEntity;
import jp.co.axio.masterMentsetSystem.repository.MRuleEntityMapper;

/**
 * 権限ルール条件一覧画面サービスクラス
 *
 * @author JCBC
 * @version 1.0
 */
@Service
public class AuthRuleListService {

    @Autowired
    MRuleEntityMapper mrMapper;

    @Autowired
    MessageSource ms;

	/**
	* ルールマスタ取得
	*
	* @param ruleId 検索画面から取得したルールID
	* @return List<Object>
	*/
	@Transactional
	public MRuleEntity selectAuthRuleMst (String ruleId) throws Exception {
		LogService.info("ルール検索一覧画面", "AuthRuleListService", "ルールマスタ取得", "開始");

		//ルールマスタ検索
		MRuleEntity mrd = mrMapper.selectByPrimaryKey(ruleId);

		LogService.info("ルール検索一覧画面", "AuthRuleListService", "ルールマスタ取得", "正常終了");
		return mrd;
	}

	/**
	* ルール情報一覧検索
	* @param form　画面の入力情報
	* @return List<RuleConditionSetDto> 取得結果
	*/
	@Transactional
	public List<RuleConditionSetDto> selectRuleList (AuthRuleListForm form) throws Exception {
		LogService.info("ルール検索一覧画面", "AuthRuleListService", "ルール条件一覧取得", "開始");

		SimpleDateFormat df = new SimpleDateFormat("yyyy/MM/dd");

		String ruleId = null;
		String ruleName = null;
		String ruleNote = null;
		java.sql.Date refDate = null;

		if (StringUtils.isNotBlank(form.getDailogRuleId())) {
			ruleId = "%" + StringUtils.trim(form.getDailogRuleId()) + "%";
		}
		if (StringUtils.isNotBlank(form.getDailogRuleName())) {
			ruleName = "%" + StringUtils.trim(form.getDailogRuleName()) + "%";
		}
		if (StringUtils.isNotBlank(form.getDailogRuleNote())) {
			ruleNote = "%" + StringUtils.trim(form.getDailogRuleNote()) + "%";
		}
		if (StringUtils.isNotBlank(form.getDailogStartDate())) {
			try {
				df.parse(form.getDailogStartDate()); //check date format with yyyy/MM/dd
				refDate = java.sql.Date.valueOf(form.getDailogStartDate().replace("/", "-"));
			}catch (Exception e) {
	        	String msg = ms.getMessage("MSTO0007M0005", new String[] {"有効基準日", e.getMessage()}, null);
	        	Exception ex = new Exception(msg);
	        	throw ex;
			}
		}

		List<RuleConditionSetDto> rt = mrMapper.selectRuleList(ruleId, ruleName, ruleNote, refDate);

		LogService.info("ルール検索一覧画面", "AuthRuleListService", "ルール条件一覧取得", "正常終了");
		return rt;
	}
}
