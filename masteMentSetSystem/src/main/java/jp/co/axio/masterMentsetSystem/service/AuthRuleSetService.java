package jp.co.axio.masterMentsetSystem.service;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.AuthRuleSetForm;
import jp.co.axio.masterMentsetSystem.dto.RuleConditionGroupDto;
import jp.co.axio.masterMentsetSystem.dto.RuleConditionItemDto;
import jp.co.axio.masterMentsetSystem.model.MRuleDetailEntity;
import jp.co.axio.masterMentsetSystem.model.MRuleEntity;
import jp.co.axio.masterMentsetSystem.model.MRuleGroupEnRec;
import jp.co.axio.masterMentsetSystem.model.MRuleGroupEntity;
import jp.co.axio.masterMentsetSystem.model.MRuleUserEntity;
import jp.co.axio.masterMentsetSystem.model.VMRuleDetailEntity;
import jp.co.axio.masterMentsetSystem.repository.MRuleDetailEntityMapper;
import jp.co.axio.masterMentsetSystem.repository.MRuleEntityMapper;
import jp.co.axio.masterMentsetSystem.repository.MRuleGroupEntityMapper;
import jp.co.axio.masterMentsetSystem.repository.MRuleUserEntityMapper;
import jp.co.axio.masterMentsetSystem.repository.VMRuleDetailEntityMapper;

/**
 * 権限ルール条件設定画面サービスクラス
 *
 * @author JCBC
 * @version 1.0
 */
@Service
public class AuthRuleSetService {

    /** プロパティファイル　ルールID採番の頭綴り*/
    @Value("${config.rule.idPrefix}")
    private String idPrefix;

    /** プロパティファイル　ルールID採番の桁数 */
    @Value("${config.rule.idNumLength:5}")
    private String idNumLength;

    @Autowired
    MRuleEntityMapper mrMapper;

    @Autowired
    MRuleDetailEntityMapper mrdMapper;

    @Autowired
    MRuleGroupEntityMapper mrgMapper;

    @Autowired
    MRuleUserEntityMapper mruMapper;

    @Autowired
    VMRuleDetailEntityMapper vmrdMapper;

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
		LogService.info("ルール条件設定画面", "AuthRuleSetService", "ルールマスタ取得", "開始");

		//ルールマスタ検索
		MRuleEntity mrd = mrMapper.selectByPrimaryKey(ruleId);

		LogService.info("ルール条件設定画面", "AuthRuleSetService", "ルールマスタ取得", "正常終了");
		return mrd;
	}

	/**
	* ルール情報取得
	*
	* @param ruleId 検索画面から取得したルールID
	* @return List<Object>
	*/
	@Transactional
	public List<Object> selectAuthRuleInfo (String ruleId) throws Exception {
		LogService.info("ルール条件設定画面", "AuthRuleSetService", "ルール情報検索", "開始");
		ArrayList<Object> rt = new ArrayList<Object>();

		//ルール情報ビュー検索
		List<VMRuleDetailEntity> lrd = vmrdMapper.selectVMRuleDetail(ruleId);
		rt.add(lrd);

		//ルール付与グループ検索
		List<MRuleGroupEnRec> lrg = mrgMapper.selectRuleJoinGroup(ruleId);
		rt.add(lrg);

		//ルールユーザー検索
		List<MRuleUserEntity> lru = mruMapper.selectRuleJoinUser(ruleId);
		rt.add(lru);

		LogService.info("ルール条件設定画面", "AuthRuleSetService", "ルール情報検索", "正常終了");
		return rt;
	}

	/**
	* ルール情報更新
	*
	* @param form　画面の入力情報
	* @return List<Object>
	*/
	@Transactional
	public int updateAuthRuleInfo (AuthRuleSetForm form) throws Exception {
		LogService.info("ルール条件設定画面", "AuthRuleSetService", "ルール情報更新", "開始");
		int rt = 0;
		String ruleId = form.getRuleId();

		//DB更新
		if (StringUtils.isBlank(ruleId)) {
			//新規登録
			ruleId = idPrefix + String.format("%0" + idNumLength + "d", mrMapper.nextRuleId());
			form.setRuleId(ruleId);

			//ルールマスタレコード編集
			MRuleEntity mRec = editMRuleRec(form);

			//ルールマスタ更新（insert)
			rt = mrMapper.insertToRule(mRec);
			if (rt <= 0) {
				LogService.info("ルール条件設定画面", "AuthRuleSetService", "ルール情報更新(0件)", "正常終了");
				return rt;
			}

			//ルール条件レコード編集
			List<MRuleDetailEntity> mdList = editRuleDetailList(form, ruleId);
			//ルール条件更新（insert)
			for (MRuleDetailEntity rd: mdList) {
				mrdMapper.insertToRuleDetail(rd);
			}

			//ルール付与グループ編集
			List<MRuleGroupEntity> mgList = editRuleGroupList(form, ruleId);
			//ルール付与グループ更新（insert)
			for (MRuleGroupEntity rg: mgList) {
				mrgMapper.insertToRuleGroup(rg);
			}

			// 個別ユーザー編集
			List<MRuleUserEntity> muList = editRuleUserList(form, ruleId);
			//ルール付与グループ更新（insert)
			for (MRuleUserEntity ru: muList) {
				mruMapper.insertToRuleUser(ru);
			}

		} else {
			//更新登録
			//ルールマスタレコード編集
			MRuleEntity mRec = editMRuleRec(form);
			//ルールマスタ更新（update)
			rt = mrMapper.updateRule(mRec);
			if (rt <= 0) {
				LogService.info("ルール条件設定画面", "AuthRuleSetService", "ルール情報更新(0件)", "正常終了");
				return rt;
			}

			//ルール条件レコード編集
			List<MRuleDetailEntity> mdList = editRuleDetailList(form, ruleId);
			//ルール条件更新（delete/insert)
			mrdMapper.deleteRuleDetail(ruleId);
			for (MRuleDetailEntity md : mdList) {
				mrdMapper.insertToRuleDetail(md);
			}

			//ルール条件レコード編集
			List<MRuleGroupEntity> mgList = editRuleGroupList(form, ruleId);
			//ルール付与グループ更新（delete/insert)
			mrgMapper.deleteRuleGroup(ruleId);
			for (MRuleGroupEntity mrg : mgList) {
				mrgMapper.insertToRuleGroup(mrg);
			}

			//ルールユーザーレコード編集
			List<MRuleUserEntity> muList = editRuleUserList(form, ruleId);
			//ルール個別ユーザー更新（delete/insert)
			mruMapper.deleteRuleUser(ruleId);
			for (MRuleUserEntity mru : muList) {
				mruMapper.insertToRuleUser(mru);
			}
		}

		LogService.info("ルール条件設定画面", "AuthRuleSetService", "ルール情報更新", "正常終了");
		return rt;
	}

	/**
	* ルール情報削除（無効化）
	*
	* @param form　画面の入力情報
	* @return int 更新件数
	*/
	@Transactional
	public int deleteAuthRuleInfo (String ruleId) throws Exception {
		LogService.info("ルール条件設定画面", "AuthRuleSetService", "ルール情報削除(ruleId="+ruleId+")", "開始");

		int rt = (int)mrMapper.deleteRule(ruleId);

		LogService.info("ルール条件設定画面", "AuthRuleSetService", "ルール情報削除(ruleId="+ruleId+")", "正常終了");
		return rt;
	}

	/**
	 * ルールマスタレコード編集
	 * @throws Exception
	 */
	public MRuleEntity editMRuleRec(AuthRuleSetForm form) throws Exception {
		MRuleEntity mrRec = new MRuleEntity();

		mrRec.setRuleId(form.getRuleId());
		mrRec.setRuleName(form.getRuleName());
		mrRec.setNote(form.getRuleNote());
		mrRec.setInvalidFlag("0");
		SimpleDateFormat df = new SimpleDateFormat("yyyy/MM/dd");
		df.setLenient(false);
        Date date = new Date();
        try {
        	date = df.parse(form.getStartDate());
    		mrRec.setStartDate(date);
        } catch (Exception e) {
        	String msg = ms.getMessage("MSTO0007M0005", new String[] {"適用開始日", e.getMessage()}, null);
        	Exception ex = new Exception(msg);
        	throw ex;
        }
        try {
        	date = df.parse(form.getEndDate());
    		mrRec.setEndDate(date);
        } catch (Exception e) {
        	String msg = ms.getMessage("MSTO0007M0005", new String[] {"適用終了日", e.getMessage()}, null);
        	Exception ex = new Exception(msg);
        	throw ex;
        }

		return mrRec;
	}

	/**
	 * 入力項目の値を解析
	 * @throws Exception
	 */
	public String parseMultItem(String itemName, String itemData, int... itemid) throws Exception  {
		StringBuilder rt = new StringBuilder("");
		String[] rc = null;

		if (StringUtils.isNotBlank(itemData)) {
			rc = itemData.split(";");
			int idx = 0;
			for (String rv: rc) {
				String[] rs = rv.split(":");
				for (int i=0; i<itemid.length; i++) {
					if (rs.length > itemid[i]) {
						rt = i<itemid.length-1 ? rt.append(rs[itemid[i]]).append(":") : rt.append(rs[itemid[i]]);
					} else {
						String msg = ms.getMessage("MSTO0007M0006", new String[] {itemName, rv}, null);
			        	Exception ex = new Exception(msg);
			        	throw ex;
					}
				}
				rt = idx<rc.length-1 ? rt.append(";") : rt.append("");
				idx++;
			}
		}
		return rt.toString();
	}

	/**
	 * ルール情報レコード編集
	 * @throws Exception
	 */
	public List<MRuleDetailEntity> editRuleDetailList(AuthRuleSetForm form, String ruleId) throws Exception {
		List<MRuleDetailEntity> mrlist = new ArrayList<MRuleDetailEntity>();
		List<RuleConditionItemDto> ruleDto = form.getRuleConditionList();

		if (StringUtils.isNotBlank(ruleId) && ruleDto != null) {
			int rno = 1;
			for( RuleConditionItemDto rcd : ruleDto) {
				if (StringUtils.isNotBlank(rcd.getRuleSetCompany())
						|| StringUtils.isNotBlank(rcd.getRuleSetEmployment())
						|| StringUtils.isNotBlank(rcd.getRuleSetOrganization())
						|| StringUtils.isNotBlank(rcd.getRuleSetPosition())) {

					MRuleDetailEntity mrd = new MRuleDetailEntity();
					mrd.setRuleId(ruleId);
					mrd.setRuleDetailId(String.valueOf(rno));
					mrd.setRuleDetailFlag("0");

					mrd.setCompanyCode(parseMultItem("会社付与条件", rcd.getRuleSetCompany(), 0));
					mrd.setEmploymentKbn(parseMultItem("雇用区分付与条件", rcd.getRuleSetEmployment(), 0));
					mrd.setOrganizationCode(parseMultItem("組織付与条件", rcd.getRuleSetOrganization(), 0, 1));
					mrd.setPositionCode(parseMultItem("役職付与条件", rcd.getRuleSetPosition(), 0, 1));

					mrlist.add(mrd);
				}
				if (StringUtils.isNotBlank(rcd.getRuleExtCompany())
						|| StringUtils.isNotBlank(rcd.getRuleExtEmployment())
						|| StringUtils.isNotBlank(rcd.getRuleExtOrganization())
						|| StringUtils.isNotBlank(rcd.getRuleExtPosition())) {

					MRuleDetailEntity mrd = new MRuleDetailEntity();
					mrd.setRuleId(ruleId);
					mrd.setRuleDetailId(String.valueOf(rno));
					mrd.setRuleDetailFlag("1");

					mrd.setCompanyCode(parseMultItem("会社除外条件", rcd.getRuleExtCompany(), 0));
					mrd.setEmploymentKbn(parseMultItem("雇用区分除外条件", rcd.getRuleExtEmployment(), 0));
					mrd.setOrganizationCode(parseMultItem("組織除外条件", rcd.getRuleExtOrganization(), 0, 1));
					mrd.setPositionCode(parseMultItem("役職除外条件", rcd.getRuleExtPosition(), 0, 1));

					mrlist.add(mrd);
				}
				rno++;
			}
		}

		return mrlist;
	}

	/**
	 *　ルールグループレコード編集
	 * @throws Exception
	 */
	public List<MRuleGroupEntity> editRuleGroupList(AuthRuleSetForm form, String ruleId) throws Exception {
		List<MRuleGroupEntity> mrlist = new ArrayList<MRuleGroupEntity>();
		List<RuleConditionGroupDto> groupDto = form.getRuleGroupList();

		if (StringUtils.isNotBlank(ruleId) && groupDto != null) {
			for (RuleConditionGroupDto rg : groupDto) {
				if (rg.isDelFlg()) {
					//削除済のグループIDを外す
					continue;
				}
				rg.setRuleId(ruleId);
				MRuleGroupEntity rgRec = new MRuleGroupEntity();
				rgRec.setRuleId(ruleId);
				rgRec.setGroupId(rg.groupId);
				mrlist.add(rgRec);
			}
		}

		return mrlist;
	}

	/**
	 *　ルールユーザーレコード編集
	 * @throws Exception
	 */
	public List<MRuleUserEntity> editRuleUserList(AuthRuleSetForm form, String ruleId) throws Exception {
		List<MRuleUserEntity> mrlist = new ArrayList<MRuleUserEntity>();

		// ユーザー付与
		String userCodeStr = form.getUserCode();
		if (StringUtils.isNotBlank(ruleId) && StringUtils.isNotBlank(userCodeStr)) {
			String[] dataSets = userCodeStr.split(";");
			for (int i = 0; i < dataSets.length; i++) {
				String oneId = (dataSets[i].split(":"))[0];

				MRuleUserEntity userData = new MRuleUserEntity();
				userData.setRuleId(ruleId);
				userData.setUserId(oneId);
				userData.setExclusionFlag("0");	// 付与
				mrlist.add(userData);
			}
		}

		// ユーザー除外
		String userExtCodeStr = form.getUserExtCode();
		if (StringUtils.isNotBlank(ruleId) && StringUtils.isNotBlank(userExtCodeStr)) {
			String[] dataSets = userExtCodeStr.split(";");
			for (int i = 0; i < dataSets.length; i++) {
				String oneId = (dataSets[i].split(":"))[0];

				MRuleUserEntity userData = new MRuleUserEntity();
				userData.setRuleId(ruleId);
				userData.setUserId(oneId);
				userData.setExclusionFlag("1");	// 除外
				mrlist.add(userData);
			}
		}

		return mrlist;
	}

}
