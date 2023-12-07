package jp.co.axio.masterMentsetSystem.controller;


import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import jp.co.axio.masterMentsetSystem.common.CheckDateFormat;
import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.AuthRuleSetForm.DeleteGroup;
import jp.co.axio.masterMentsetSystem.controller.AuthRuleSetForm.SaveGroup;
import jp.co.axio.masterMentsetSystem.dto.RuleConditionGroupDto;
import jp.co.axio.masterMentsetSystem.dto.RuleConditionItemDto;
import jp.co.axio.masterMentsetSystem.dto.RuleConditionOptDto;
import jp.co.axio.masterMentsetSystem.model.MRuleEntity;
import jp.co.axio.masterMentsetSystem.model.MRuleGroupEnRec;
import jp.co.axio.masterMentsetSystem.model.MRuleUserEntity;
import jp.co.axio.masterMentsetSystem.model.VMRuleDetailEntity;
import jp.co.axio.masterMentsetSystem.service.AuthRuleSetService;

/**
 * ルール条件設定画面
 *
 * @author JCBC
 * @version 1.0
 */
@Controller
public class AuthRuleSetController extends accessController {

	//ルール条件選択：新規追加
	private static final String newRuleOpt = "0";
	//ルール条件選択：付与条件
	private static final String ruleSetKbn = "0";

	//モダール画面連携機能
	//ルール検索
	private static final String ruleSearch = "ruleSearch";
	private static final String groupSelect = "groupSelect";
	//ルール検索以外のモダール画面の結果がリクエストしないため、コメントアウトする
//	private static final String companySelect = "companySelect";
//	private static final String employmentKbnSelect = "employmentKbnSelect";
//	private static final String organizationSelect = "organizationSelect";
//	private static final String positionSelect = "positionSelect";

    /** 自画面のHTMLテンプレート */
    private final String OWN_PAGE = "AuthRuleSet/authRuleSet";

    /** 初期ページ　*/
    private final String REDIRECT_PAGE = "redirect:./authRuleSet";

	/** 自処理対象画面名 */
	private static final String OWN_TITLE = "ルール条件設定画面";

	/** ログインコントローラ */
	@Autowired
	LoginController loginController;

    @Autowired
    AuthRuleSetService authRuleSetService;

    @Autowired
    MessageSource ms;

    /** プロパティファイル　ユーザ付与フラグ */
    @Value("${config.rule.userSetFlag:0}")
    private String userSetFlag;

	/**
	 * 初期処理
	 *
	 * @throws Exception
	 *
	 */
	@SuppressWarnings("unchecked")
	@RequestMapping("/authRuleSet")
	public ModelAndView index(@ModelAttribute("AuthRuleSetForm") AuthRuleSetForm form, BindingResult result, HttpServletRequest request, RedirectAttributes redirectAttributes)  {
		LogService.info("ルール条件設定画面", "AuthRuleSetController", "初期処理", "開始");


		/**
		 * 2022/02/07　ログインチェック追加 開始
		 */
		// 既存処理コメントアウト
		// ModelAndView modelAndView = new ModelAndView();

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);
		if (modelAndView != null) {
			return modelAndView;// ログイン画面へ遷移
		} else {
			// 2022/06/22　権限チェック追加
			modelAndView = loginController.checkAdmin(OWN_TITLE, redirectAttributes);
			if (modelAndView != null) {
				return modelAndView;// ログイン画面へ遷移
			} else {
				modelAndView = new ModelAndView();
			}
		}
		/**
		 * 2022/02/07　ログインチェック追加 終了
		 */

		//アクセストークン設定 二重送信防止
		saveAccessToken(form);

		//モダール画面連携項目値を格納
		String func = form.getReflectFunction();
		String param = form.getParamVal();

		//モダール画面連携項目をクリア
		form.setReflectFunction("");
		form.setParamVal("");

		try {
			if(StringUtils.isBlank(func)) {
				initForm(form);
				//demoForm(form);
			} else {
				if ( ruleSearch.equals(func) ) {
					//ルール検索ボタン押下より
			        String ruleId = null;

					JsonElement jelement  = StringUtils.isBlank(param) ? null : new JsonParser().parse(param);
					JsonArray jarray = (jelement == null ? null : jelement.getAsJsonArray());
			        if (jarray != null && jarray.size() > 0) {
			        	//一覧画面から選択されたルールIDを取得
			        	ruleId = jarray.get(0).getAsJsonObject().get("ruleId").getAsString();
			        }

			        if (StringUtils.isBlank(ruleId)) {
			        	//一覧画面から未選択の場合、画面のクリアする
			        	initForm(form);

			        } else {
			        	//一覧画面から選択されたルールIDにより紐づけ情報を検索して表示する
			        	MRuleEntity mrule = authRuleSetService.selectAuthRuleMst(ruleId);

			        	if (mrule == null) {
							String msg = ms.getMessage("MSTO0007M0001", new String[] {ruleId}, null);
							form.setErrMessage(msg);
							initForm(form);
			        	} else {
					        List<Object> retList = authRuleSetService.selectAuthRuleInfo(ruleId);
					        List<VMRuleDetailEntity> rtv = (List<VMRuleDetailEntity>)retList.get(0);
					        List<MRuleGroupEnRec> mrg = (List<MRuleGroupEnRec>)retList.get(1);
					        List<MRuleUserEntity> mru = (List<MRuleUserEntity>)retList.get(2);
					        setForm(form, mrule, rtv, mrg, mru);
						}
			        }
				}
				else if (groupSelect.equals(func)) {
					//グループ選択ボタン押下より
					List<RuleConditionGroupDto> lgroup = new ArrayList<RuleConditionGroupDto>();
					form.setRuleGroupList(lgroup);

			        JsonElement jelement  = StringUtils.isBlank(param) ? null : new JsonParser().parse(param);
			        JsonArray  jarray = (jelement == null ? null : jelement.getAsJsonArray());
			        if (jarray != null && jarray.size() > 0) {
			        	for (int i=0; i<jarray.size(); i++) {
			        		String groupId = jarray.get(i).getAsJsonObject().get("groupId").getAsString();
			        		String groupNameJp = jarray.get(i).getAsJsonObject().get("groupNameJp").getAsString();
			        		String groupNameEn = jarray.get(i).getAsJsonObject().get("groupNameEn").getAsString();
			        		String startDate = jarray.get(i).getAsJsonObject().get("startDate").getAsString();
			        		String endDate = jarray.get(i).getAsJsonObject().get("endDate").getAsString();

			        		RuleConditionGroupDto gp = new RuleConditionGroupDto();
			        		gp.setRuleId(form.getRuleId());
			        		gp.setGroupId(groupId);
			        		gp.setGroupNameJP(groupNameJp);
			        		gp.setGroupNameEn(groupNameEn);
			        		gp.setStartDate(startDate);
			        		gp.setEndDate(endDate);
			        		gp.setDelFlg(false);
			        		lgroup.add(gp);
			        	}
			        	Collections.sort(lgroup, new Comparator<RuleConditionGroupDto>(){
			        	      public int compare(RuleConditionGroupDto r1, RuleConditionGroupDto r2) {
			        	        return r1.getGroupId().compareTo(r2.getGroupId());
			        	      }
			        	    });
			        }
				}
			}
		} catch (Exception e) {
			LogService.system("ルール条件設定画面", "AuthRuleSetController", "ルール条件設定画面初期処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			String msg = ms.getMessage("ERR001", null, null);
			form.setErrMessage(msg);
			LogService.info("ルール条件設定画面", "AuthRuleSetController", "ルール条件設定画面初期処理", "··異常終了");
			return modelAndView;
		} finally {
			modelAndView.addObject("AuthRuleSetForm", form);
			modelAndView.setViewName(OWN_PAGE);
		}

		LogService.info("ルール条件設定画面", "AuthRuleSetController", "初期処理", "正常終了");
		return modelAndView;
	}

	/**
	 * 保存処理
	 *
	 * @throws Exception
	 *
	 */
	@RequestMapping("/authRuleSetSave")
	public ModelAndView save(@ModelAttribute("AuthRuleSetForm") @Validated(SaveGroup.class) AuthRuleSetForm form, BindingResult result, HttpServletRequest request, Model model)  {
		LogService.info("ルール条件設定画面", "AuthRuleSetController", "保存処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

		//二重送信、ページ不正アクセス防止
		if (!checkAccessToken(form)) {
			modelAndView.setViewName(REDIRECT_PAGE);
			LogService.info("ルール条件設定画面", "AuthRuleSetController", "保存処理", "二重送信チェックエラー終了");
			return modelAndView;
		}
		//適用開始日チェック
        if (!CheckDateFormat.checkDateYMD(form.getStartDate())) {
        	String errmsg = ms.getMessage("MSTO0007M0005", new String[] {"「適用開始日」", form.getStartDate()}, null);
        	result.reject("", errmsg); // エラーメッセージ表示
        }
		//適用終了日チェック
        if (!CheckDateFormat.checkDateYMD(form.getEndDate())) {
        	String errmsg = ms.getMessage("MSTO0007M0005", new String[] {"「適用終了日」", form.getEndDate()}, null);
        	result.reject("", errmsg); // エラーメッセージ表示
        }
        if (result.hasErrors()) {
    		modelAndView.addObject("AuthRuleSetForm", form);
    		modelAndView.setViewName(OWN_PAGE);
            return modelAndView;
        }

        try {
			String ruleId = StringUtils.isBlank(form.getRuleId()) ? "新規" : form.getRuleId();
        	int rt = authRuleSetService.updateAuthRuleInfo(form);

			if (rt <= 0) {
				String msg = ms.getMessage("MSTO0007M0003", new String[] { ruleId }, null);
				form.setErrMessage(msg);

				LogService.info("ルール条件設定画面", "AuthRuleSetController", "ルール条件設定画面更新処理(0件更新)", "警告");
			} else {
				//initForm(form);

				//制御フラグをクリア
				form.setChangedFlg("");
				form.setEditFlg("");

				//モダール画面連携項目をクリア
				form.setReflectFunction("");
				form.setParamVal("");

		        // 完了メッセージ
		        String msg = ms.getMessage("CMN0003", new String[] { "ルール保存" }, null);
		        model.addAttribute("axioMessage", msg);
		    }
		} catch (Exception e) {
			LogService.system("ルール条件設定画面", "AuthRuleSetController", "ルール条件設定画面削除処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			String msg = ms.getMessage("ERR001", null, null);
			form.setErrMessage(msg);
			LogService.info("ルール条件設定画面", "AuthRuleSetController", "ルール条件設定画面削除処理", "··異常終了");
			return modelAndView;
		} finally {
			modelAndView.addObject("AuthRuleSetForm", form);
			modelAndView.setViewName(OWN_PAGE);
		}

		//新しいトーケン設定
		saveAccessToken(form);

		modelAndView.addObject("AuthRuleSetForm", form);
		modelAndView.setViewName(OWN_PAGE);
		LogService.info("ルール条件設定画面", "AuthRuleSetController", "保存処理", "正常終了");
		return modelAndView;
	}

	/**
	 * 削除処理
	 *
	 * @throws Exception
	 *
	 */
	@RequestMapping("/authRuleSetDelete")
	public ModelAndView delete(@ModelAttribute("AuthRuleSetForm") @Validated(DeleteGroup.class) AuthRuleSetForm form, BindingResult result, HttpServletRequest request, Model model)  {
		LogService.info("ルール条件設定画面", "AuthRuleSetController", "削除処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

		//二重送信、ページ不正アクセス防止
		if (!checkAccessToken(form)) {
			modelAndView.setViewName(REDIRECT_PAGE);
			LogService.info("ルール条件設定画面", "AuthRuleSetController", "削除処理", "二重送信チェックエラー終了");
			return modelAndView;
		}

        if (result.hasErrors()) {
    		modelAndView.addObject("AuthRuleSetForm", form);
    		modelAndView.setViewName(OWN_PAGE);
            return modelAndView;
        }

		try {
			String ruleId = form.getRuleId();
			int rt = authRuleSetService.deleteAuthRuleInfo(form.getRuleId());

			if (rt <= 0) {
				String msg = ms.getMessage("MSTO0007M0004", new String[] { ruleId }, null);
				form.setErrMessage(msg);

				LogService.info("ルール条件設定画面", "AuthRuleSetController", "ルール条件設定画面削除処理(0件削除)", "警告");
			} else {
				initForm(form);

				// 完了メッセージ
				String msg = ms.getMessage("CMN0003", new String[] { "ルール削除" }, null);
				model.addAttribute("axioMessage", msg);
			}
		} catch (Exception e) {
			LogService.system("ルール条件設定画面", "AuthRuleSetController", "ルール条件設定画面削除処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			String msg = ms.getMessage("ERR001", null, null);
			form.setErrMessage(msg);
			LogService.info("ルール条件設定画面", "AuthRuleSetController", "ルール条件設定画面削除処理", "··異常終了");
			return modelAndView;
		} finally {
			modelAndView.addObject("AuthRuleSetForm", form);
			modelAndView.setViewName(OWN_PAGE);
		}

		//新しいトーケン設定
		saveAccessToken(form);

		modelAndView.addObject("AuthRuleSetForm", form);
		modelAndView.setViewName(OWN_PAGE);
		LogService.info("ルール条件設定画面", "AuthRuleSetController", "削除処理", "正常終了");
		return modelAndView;
	}

	/**
	 * クリア処理
	 *
	 * @throws Exception
	 *
	 */
	@RequestMapping("/authRuleSetClear")
	public ModelAndView clear(@ModelAttribute("AuthRuleSetForm") AuthRuleSetForm form, BindingResult result, HttpServletRequest request)  {
		LogService.info("ルール条件設定画面", "AuthRuleSetController", "クリア処理", "開始");
		ModelAndView modelAndView = new ModelAndView();
		initForm(form);
		modelAndView.addObject("AuthRuleSetForm", form);
		modelAndView.setViewName(REDIRECT_PAGE);
		LogService.info("ルール条件設定画面", "AuthRuleSetController", "クリア処理", "正常終了");
		return modelAndView;
	}

	/**
	 * 条件一覧更新処理
	 *
	 * @throws Exception
	 */
	@RequestMapping("/authRuleSetUpdateList")
	public ModelAndView updateList(@ModelAttribute("AuthRuleSetForm") AuthRuleSetForm form, BindingResult result, HttpServletRequest request)  {
		LogService.info("ルール条件設定画面", "AuthRuleSetController", "条件一覧更新処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

//		//二重送信、ページ不正アクセス防止
//		if (!checkAccessToken(form)) {
//			modelAndView.setViewName(REDIRECT_PAGE);
//			LogService.info("ルール条件設定画面", "AuthRuleSetController", "条件一覧更新処理", "二重送信チェックエラー終了");
//			return modelAndView;
//		}

		List<RuleConditionItemDto> rdl = form.getRuleConditionList();
		if (rdl==null) {
			rdl = new ArrayList<RuleConditionItemDto>();
			form.setRuleConditionList(rdl);
		}
		int cnt = rdl.size();
		int idx = 0;

		if (newRuleOpt.equals(form.getCurrentOptNo())) {
			RuleConditionItemDto rct = new RuleConditionItemDto();
			//設定済条件一覧に追加
			if (ruleSetKbn.equals(form.getCurrentOptKbn())) {
				//付与条件、リストの先頭に追加
				rct.setRuleId(form.getRuleId());
				rct.setRuleDetailNo(String.valueOf(cnt+1));
				rct.setRuleSetCompany(form.getCompanyCode());
				rct.setRuleSetEmployment(form.getEmploymentCode());
				rct.setRuleSetOrganization(form.getOrganizationCode());
				rct.setRuleSetPosition(form.getPositionCode());
//				rdl.add(0, rct);
				rdl.add(rct);

				//セレクトの名称リストを更新
				setSelectOptionList(form);

				//初期選択値設定
//				form.setCurrentOptValue("条件1 付与条件");
//				form.setCurrentOptNo("1");
				form.setCurrentOptValue("条件" + String.valueOf(cnt+1) + " 付与条件");
				form.setCurrentOptNo(String.valueOf(cnt+1));
				form.setCurrentOptKbn("0");
			} else {
				//除外条件、リストの先頭に追加
				rct.setRuleId(form.getRuleId());
				rct.setRuleDetailNo(String.valueOf(cnt+1));
				rct.setRuleExtCompany(form.getCompanyCode());
				rct.setRuleExtEmployment(form.getEmploymentCode());
				rct.setRuleExtOrganization(form.getOrganizationCode());
				rct.setRuleExtPosition(form.getPositionCode());
//				rdl.add(0, rct);
				rdl.add(rct);

				//セレクトの名称リストを更新
				setSelectOptionList(form);

				//初期選択値設定
//				form.setCurrentOptValue("条件1 除外条件");
//				form.setCurrentOptNo("1");
				form.setCurrentOptValue("条件" + String.valueOf(cnt+1) + " 除外条件");
				form.setCurrentOptNo(String.valueOf(cnt+1));
				form.setCurrentOptKbn("1");
			}

		} else {
			idx = Integer.parseInt(form.getCurrentOptNo()) - 1;

			if (idx >= 0 && idx < cnt) {
				RuleConditionItemDto rct = rdl.get(idx);
				//設定済条件一覧を更新
				if (ruleSetKbn.equals(form.getCurrentOptKbn())) {
					//付与条件、該当するレコードを書き換え
					rct.setRuleSetCompany(form.getCompanyCode());
					rct.setRuleSetEmployment(form.getEmploymentCode());
					rct.setRuleSetOrganization(form.getOrganizationCode());
					rct.setRuleSetPosition(form.getPositionCode());

				} else {
					//除外条件、該当するレコードを書き換え
					rct.setRuleExtCompany(form.getCompanyCode());
					rct.setRuleExtEmployment(form.getEmploymentCode());
					rct.setRuleExtOrganization(form.getOrganizationCode());
					rct.setRuleExtPosition(form.getPositionCode());
				}
			}
		}

		modelAndView.addObject("AuthRuleSetForm", form);
		modelAndView.setViewName(OWN_PAGE);
		LogService.info("ルール条件設定画面", "AuthRuleSetController", "条件一覧更新処理", "正常終了");
		return modelAndView;
	}

	/**
	 * 条件一覧削除処理
	 *
	 * @throws Exception
	 */
	@RequestMapping("/authRuleSetDeleteList")
	public ModelAndView deleteList(@ModelAttribute("AuthRuleSetForm") AuthRuleSetForm form, BindingResult result, HttpServletRequest request)  {
		LogService.info("ルール条件設定画面", "AuthRuleSetController", "条件一覧削除処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

//		//二重送信、ページ不正アクセス防止
//		if (!checkAccessToken(form)) {
//			modelAndView.setViewName(REDIRECT_PAGE);
//			LogService.info("ルール条件設定画面", "AuthRuleSetController", "条件一覧削除処理", "二重送信チェックエラー終了");
//			return modelAndView;
//		}

		int idx = Integer.parseInt(form.getCurrentOptNo()) - 1;
		if (idx >= 0) {
			List<RuleConditionItemDto> rdl = form.getRuleConditionList();
			if (rdl != null || rdl.size() > idx) {
				RuleConditionItemDto ritem = rdl.get(idx);

				//設定済条件一覧を削除
				if (ruleSetKbn.equals(form.getCurrentOptKbn())) {
					//付与条件
					ritem.setRuleSetCompany("");
					ritem.setRuleSetEmployment("");
					ritem.setRuleSetOrganization("");
					ritem.setRuleSetPosition("");
				} else {
					//除外条件
					ritem.setRuleExtCompany("");
					ritem.setRuleExtEmployment("");
					ritem.setRuleExtOrganization("");
					ritem.setRuleExtPosition("");
				}

				//付与条件と除外条件が両方空の場合、当該レコードをリストから外す
				StringBuilder rc = new StringBuilder()
						.append(ritem.ruleSetCompany )
						.append(ritem.ruleSetEmployment )
						.append(ritem.ruleSetOrganization )
						.append(ritem.ruleSetPosition )
						.append(ritem.ruleExtCompany )
						.append(ritem.ruleExtEmployment )
						.append(ritem.ruleExtOrganization )
						.append(ritem.ruleExtPosition );

				if (rc.length()<=0) {
					rdl.remove(idx);
				}
				//セレクトの名称リストを更新
				setSelectOptionList(form);

				//ルール入力項目初期化
				form.setCompanyCode("");
				form.setEmploymentCode("");
				form.setOrganizationCode("");
				form.setPositionCode("");

				//初期選択値設定
				form.setCurrentOptValue("新規 付与条件");
				form.setCurrentOptNo("0");
				form.setCurrentOptKbn("0");
			}
		}

		modelAndView.addObject("AuthRuleSetForm", form);
		modelAndView.setViewName(OWN_PAGE);
		LogService.info("ルール条件設定画面", "AuthRuleSetController", "条件一覧削除処理", "正常終了");
		return modelAndView;
	}

	/**
	 * formの情報を初期化する。
	 *
	 * @param form
	 * @return form
	 */
	private AuthRuleSetForm initForm(AuthRuleSetForm form) {

		//制御フラグをクリア
		form.setChangedFlg("");
		form.setEditFlg("");

		//モダール画面連携項目をクリア
		form.setReflectFunction("");
		form.setParamVal("");

		//ルール入力項目初期化
		form.setRuleId("");
		form.setRuleName("");
		form.setRuleNote("");
		//デフォルート開始日、終了日設定
		form.setStartDate(new SimpleDateFormat("yyyy/MM/dd").format(new Date()));
		form.setEndDate("2999/12/31");

		//ルール条件セレクト初期化
		List<RuleConditionOptDto> lopt = getNewRuleOptList();
		form.setRuleSelectList(lopt);

		//初期選択値設定
		form.setCurrentOptValue("新規 付与条件");
		form.setCurrentOptNo("0");
		form.setCurrentOptKbn("0");

		//ルール条件テキストエリア初期化
		form.setCompanyCode("");
		form.setEmploymentCode("");
		form.setOrganizationCode("");
		form.setPositionCode("");

		//設定済みルール条件リスト初期化
		List<RuleConditionItemDto> lrule = new ArrayList<RuleConditionItemDto>();
		form.setRuleConditionList(lrule);

		//設定済みルールグループリスト初期化
		List<RuleConditionGroupDto> lgroup = new ArrayList<RuleConditionGroupDto>();
		form.setRuleGroupList(lgroup);

		// ユーザー個別付与のフラグ
		form.setUserSetFlag(userSetFlag);

		return form;
	}

	/**
	 * ルール条件セレクトのリストを設定する
	 */
	private void setSelectOptionList(AuthRuleSetForm form) {
		List<RuleConditionOptDto> lopt = getNewRuleOptList();
		List<RuleConditionItemDto> rdl = form.getRuleConditionList();

		if (rdl != null ) {
			for (int idx=0; idx<rdl.size(); idx++) {
				// ルール条件セレクトオプション一覧に値を追加
				String rcnts = String.valueOf(idx+1);
				RuleConditionOptDto ldto = new RuleConditionOptDto(rcnts, "0", "条件" + rcnts + " 付与条件");
				RuleConditionOptDto rdto = new RuleConditionOptDto(rcnts, "1", "条件" + rcnts + " 除外条件");
				lopt.add(ldto);
				lopt.add(rdto);
			}
		}
		form.setRuleSelectList(lopt);
	}

	/**
	 * formの情報を設定する。
	 *
	 * @param form フォーム
	 * @param rtv  ルール条件レコードリスト
	 * @param mrg  ルール付与グループレコードリスト
	 * @param mru  ルールユーザーレコードリスト
	 * @return form
	 */
	private AuthRuleSetForm setForm(AuthRuleSetForm form, MRuleEntity mrule, List<VMRuleDetailEntity> rtv,
			List<MRuleGroupEnRec> mrg, List<MRuleUserEntity> mru ) {

		//制御フラグをクリア
		form.setChangedFlg("");
		form.setEditFlg("");

		//モダール画面連携項目をクリア
		form.setReflectFunction("");
		form.setParamVal("");

		if (mrule == null) {
			initForm(form);
			return form;
		}

		//ルールマスタ項目
		form.setRuleId(mrule.getRuleId());
		form.setRuleName(mrule.getRuleName());
		form.setRuleNote(mrule.getNote());

		SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
		form.setStartDate(sdf.format(mrule.getStartDate()));
		form.setEndDate(sdf.format(mrule.getEndDate()));

		//初期選択値設定
		form.setCurrentOptValue("新規 付与条件");
		form.setCurrentOptNo("0");
		form.setCurrentOptKbn("0");

		//テキストエリアクリア
		form.setCompanyCode("");
		form.setEmploymentCode("");
		form.setOrganizationCode("");
		form.setPositionCode("");

		//ルール条件セレクトオプション一覧
		List<RuleConditionOptDto> lopt = getNewRuleOptList();
		form.setRuleSelectList(lopt);

		//設定済ルール条件リスト
		List<RuleConditionItemDto> lrule = new ArrayList<RuleConditionItemDto>();
		form.setRuleConditionList(lrule);

		int rcnt = 1;
		for (int idx=0; idx<rtv.size(); idx++, rcnt++) {
			// ルール条件セレクトオプション一覧に値を追加
			String rcnts = String.valueOf(rcnt);
			RuleConditionOptDto ldto = new RuleConditionOptDto(rcnts, "0", "条件" + rcnts + " 付与条件");
			RuleConditionOptDto rdto = new RuleConditionOptDto(rcnts, "1", "条件" + rcnts + " 除外条件");
			lopt.add(ldto);
			lopt.add(rdto);

			// 設定済ルール条件リストに値を追加
			VMRuleDetailEntity left = rtv.get(idx);
			VMRuleDetailEntity right = idx+1<rtv.size() ? rtv.get(idx+1) : new VMRuleDetailEntity();
			RuleConditionItemDto ritem = new RuleConditionItemDto();

			ritem.setRuleId(left.getRuleId());
			ritem.setRuleDetailNo(left.getRuleDetailId());

			if ("0".equals(left.getRuleDetailFlag())) {
				//ルール設定条件
				ritem.setRuleSetCompany(left.getCompany());
				ritem.setRuleSetEmployment(left.getEmployment());
				ritem.setRuleSetOrganization(left.getOrganization());
				ritem.setRuleSetPosition(left.getPosition());
			}
			else if ("1".equals(left.getRuleDetailFlag())) {
				//ルール除外条件
				ritem.setRuleExtCompany(left.getCompany());
				ritem.setRuleExtEmployment(left.getEmployment());
				ritem.setRuleExtOrganization(left.getOrganization());
				ritem.setRuleExtPosition(left.getPosition());
			}

			if (StringUtils.equals(left.getRuleDetailId(), right.getRuleDetailId())) {
				idx++;
				if ("0".equals(right.getRuleDetailFlag())) {
					//ルール設定条件
					ritem.setRuleSetCompany(right.getCompany());
					ritem.setRuleSetEmployment(right.getEmployment());
					ritem.setRuleSetOrganization(right.getOrganization());
					ritem.setRuleSetPosition(right.getPosition());
				}
				else if ("1".equals(right.getRuleDetailFlag())) {
					//ルール除外条件
					ritem.setRuleExtCompany(right.getCompany());
					ritem.setRuleExtEmployment(right.getEmployment());
					ritem.setRuleExtOrganization(right.getOrganization());
					ritem.setRuleExtPosition(right.getPosition());
				}
			}
			lrule.add(ritem);

 		}

		//設定済グループ一覧編集
		List<RuleConditionGroupDto> lgroup = new ArrayList<RuleConditionGroupDto>();
		form.setRuleGroupList(lgroup);

		for (MRuleGroupEnRec rg : mrg) {
			RuleConditionGroupDto rgp = new RuleConditionGroupDto();
			rgp.setRuleId(rg.getRuleId());
			rgp.setGroupId(rg.getGroupId());
			rgp.setGroupNameJP(rg.getGroupNameJp());
			rgp.setGroupNameEn(rg.getGroupNameEn());
			rgp.setStartDate(sdf.format(rg.getStartDate()));
			rgp.setEndDate(sdf.format(rg.getEndDate()));
			rgp.setDelFlg("0".equals(rg.getInvalidFlag())?false:true);
			lgroup.add(rgp);
		}

		// 設定済みユーザー編集
		String userStr =  "";
		String userExtStr = "";
		for (MRuleUserEntity ru : mru) {
			if ("1".equals(ru.getExclusionFlag())) {
				// 除外ユーザーリスト
				if (StringUtils.isNotBlank(userExtStr)) {
					userExtStr += ";";
				}
				userExtStr += ru.getUserId();
			} else {
				// 付与ユーザーリスト
				if (StringUtils.isNotBlank(userStr)) {
					userStr += ";";
				}
				userStr += ru.getUserId();
			}
		}
		form.setUserCode(userStr);
		form.setUserExtCode(userExtStr);

		// ユーザー個別付与のフラグ
		form.setUserSetFlag(userSetFlag);

		return form;
	}

	/**
	 * 新規条件のドロップダウン用リスト取得
	 * @return
	 */
	private List<RuleConditionOptDto> getNewRuleOptList() {
		List<RuleConditionOptDto> lopt = new ArrayList<RuleConditionOptDto>();
		RuleConditionOptDto rcod = new RuleConditionOptDto();
		rcod.setOptValue("新規 付与条件");
		rcod.setOptNo("0");
		rcod.setOptKbn("0");
		lopt.add(rcod);

		rcod = new RuleConditionOptDto();
		rcod.setOptValue("新規 除外条件");
		rcod.setOptNo("0");
		rcod.setOptKbn("1");
		lopt.add(rcod);

		return lopt;
	}
 }


