package jp.co.axio.masterMentsetSystem.controller;


import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

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

import jp.co.axio.masterMentsetSystem.common.CheckDateFormat;
import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.AuthGroupSetForm.SaveGroup;
import jp.co.axio.masterMentsetSystem.dto.AuthGroupSetDto;
import jp.co.axio.masterMentsetSystem.model.MGroupEntity;
import jp.co.axio.masterMentsetSystem.service.AuthGroupSetService;

/**
 * グループ設定画面
 *
 * @author AXIO
 * @version 1.0
 */
@Controller
public class AuthGroupSetController extends accessController {

    /** 自画面のHTMLテンプレート */
    private final String OWN_PAGE = "AuthGroupSet/authGroupSet";

    /** 初期ページ　*/
    private final String REDIRECT_PAGE = "redirect:./authGroupSet";

    /** プロパティファイル　グループID採番の頭綴り*/
    @Value("${config.group.idPrefix}")
    private String idPrefix;

    /** プロパティファイル　グループID採番の桁数 */
    @Value("${config.group.idNumLength:4}")
    private String idNumLength;

	@Autowired
	AuthGroupSetService authGroupSetService;

    @Autowired
    MessageSource ms;

	/**
	 * 初期処理
     * @param form
     * @param result
     * @param request
     * @return
     */
    @RequestMapping("/authGroupSet")
    public ModelAndView index(@ModelAttribute("AuthGroupSetForm") AuthGroupSetForm form, BindingResult result, HttpServletRequest request) {

		LogService.info("グループ設定画面処理", "AuthGroupSetController", "初期処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

		//アクセストークン設定 二重送信防止
		saveAccessToken(form);

		//モダール画面連携項目をクリア
		form.setReflectFunction("");
		form.setParamVal("");

		// ★グループ一覧検索結果の場合、js側、formに設定している
		String groupId = form.getGroupId();
	    try {

	    	if (groupId != null && !groupId.isEmpty()) {
				// グループ関連ルールリストの設定
	    		List<AuthGroupSetDto> rulelist = authGroupSetService.selectGroupRuleList(groupId);
    			form.setGroupRuleList(rulelist);
	    	} else {
	    		// 画面クリア
	    		resetFormSearch(form);
			}
		} catch (Exception e) {
			LogService.system("グループ設定画面処理", "AuthGroupSetController", "初期処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			String msg = ms.getMessage("ERR001", null, null);
			form.setErrMessage(msg);
			LogService.info("グループ設定画面処理", "AuthGroupSetController", "初期処理", "··異常終了");
			return modelAndView;
		} finally {
			modelAndView.addObject("AuthGroupSetForm", form);
			modelAndView.setViewName(OWN_PAGE);
		}

		LogService.info("グループ設定画面処理", "AuthGroupSetController", "初期処理", "正常終了");
    	return modelAndView;
    }


	/**
	 * 保存処理
	 *
	 * @throws Exception
	 *
	 */
	@RequestMapping("/authGroupSetSave")
	public ModelAndView save(@ModelAttribute("AuthGroupSetForm") @Validated(SaveGroup.class) AuthGroupSetForm form, BindingResult result, HttpServletRequest request, Model model)  {
		LogService.info("グループ設定画面処理", "AuthGroupSetController", "保存処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

		//二重送信、ページ不正アクセス防止
		if (!checkAccessToken(form)) {
			modelAndView.setViewName(REDIRECT_PAGE);
			LogService.info("グループ設定画面処理", "AuthGroupSetController", "保存処理", "二重送信チェックエラー終了");
			return modelAndView;
		}

		try {

			//適用開始日チェック
	        if (!CheckDateFormat.checkDateYMD(form.getGroupStartDate())) {
	        	String errmsg = ms.getMessage("MSTO0006M0005", new String[] {"「適用開始日」", form.getGroupStartDate()}, null);
	        	result.reject("", errmsg); // エラーメッセージ表示
	        }
			//適用終了日チェック
	        if (!CheckDateFormat.checkDateYMD(form.getGroupEndDate())) {
	        	String errmsg = ms.getMessage("MSTO0006M0005", new String[] {"「適用終了日」", form.getGroupEndDate()}, null);
	        	result.reject("", errmsg); // エラーメッセージ表示
	        }
	        // グループ名重複チェック
	        if (authGroupSetService.checkByGroupName(form.getGroupNameJp(), form.getGroupId())) {
	        	String errmsg = ms.getMessage("MSTO0006M0008", new String[] {form.getGroupNameJp()}, null);
	        	result.reject("", errmsg); // エラーメッセージ表示
	        }

	        if (result.hasErrors()) {
	    		modelAndView.addObject("AuthGroupSetForm", form);
	    		modelAndView.setViewName(OWN_PAGE);
	            return modelAndView;
	        }

	        String groupId = form.getGroupId();

			MGroupEntity record = new MGroupEntity();
    		record.setGroupNameEn(form.getGroupNameEn());
    		record.setGroupNameJp(form.getGroupNameJp());
    		record.setStartDate(convDate(form.getGroupStartDate(),"適用開始日"));
    		record.setEndDate(convDate(form.getGroupEndDate(),"適用終了日"));
    		record.setNote(form.getGroupDetail());
    		record.setInvalidFlag("0");

    		int rt = 0;
    		// 現在日付
    		Calendar nowCal = Calendar.getInstance();
    		if (groupId != null && !groupId.isEmpty()) {
				// グループ更新
        		record.setGroupId(groupId);
        		record.setUpdaterId("グループ設定画面");
        		record.setUpdateTs(nowCal.getTime());
        		rt = authGroupSetService.updateGroup(record);
	    	} else {
	    		// グループID採番
	    		groupId = idPrefix + buriesZero(authGroupSetService.getNewId(), Integer.parseInt(idNumLength));

	    		// 画面に設定
	    		form.setGroupId(groupId);
	    		// DBに
	    		record.setGroupId(groupId);
	    		record.setRegisterId("グループ設定画面");
	    		record.setRegistTs(nowCal.getTime());
        		record.setUpdaterId("グループ設定画面");
        		record.setUpdateTs(nowCal.getTime());
				// グループ新規登録
        		rt = authGroupSetService.insertGroup(record);
	    	}

			if (rt <= 0) {
				String msg = ms.getMessage("MSTO0006M0003", new String[] { groupId }, null);
				form.setErrMessage(msg);

				LogService.info("グループ設定画面", "AuthGroupSetController", "グループ設定画面更新処理(0件更新)", "警告");
			} else {
		    	// グループ関連ルールリストの設定
				form.setGroupRuleList(authGroupSetService.selectGroupRuleList(groupId));

				// 画面クリア
	    		//resetFormSearch(form);
				//制御フラグをクリア
				form.setChangedFlg("");
				form.setEditFlg("");

		        // 完了メッセージ
		        String msg = ms.getMessage("CMN0003", new String[] { "グループ保存" }, null);
		        model.addAttribute("axioMessage", msg);
			}

		} catch (Exception e) {
			LogService.system("グループ設定画面処理", "AuthGroupSetController", "保存処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			String msg = ms.getMessage("ERR001", null, null);
			form.setErrMessage(msg);
			LogService.info("グループ設定画面処理", "AuthGroupSetController", "保存処理", "··異常終了");
			return modelAndView;
		} finally {
			modelAndView.addObject("AuthGroupSetForm", form);
			modelAndView.setViewName(OWN_PAGE);
		}

		//新しいトーケン設定
		saveAccessToken(form);

		LogService.info("グループ設定画面処理", "AuthGroupSetController", "保存処理", "正常終了");
    	return modelAndView;
	}

	/**
	 * 削除処理
	 *
	 * @throws Exception
	 *
	 */
	@RequestMapping("/authGroupSetDelete")
	public ModelAndView delete(@ModelAttribute("AuthGroupSetForm") @Validated(SaveGroup.class) AuthGroupSetForm form, BindingResult result, HttpServletRequest request, Model model)  {
		LogService.info("グループ設定画面処理", "AuthGroupSetController", "削除処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

		//二重送信、ページ不正アクセス防止
		if (!checkAccessToken(form)) {
			modelAndView.setViewName(REDIRECT_PAGE);
			LogService.info("グループ設定画面処理", "AuthGroupSetController", "削除処理", "二重送信チェックエラー終了");
			return modelAndView;
		}

        if (result.hasErrors()) {
    		modelAndView.addObject("AuthGroupSetForm", form);
    		modelAndView.setViewName(OWN_PAGE);
            return modelAndView;
        }

		try {
			int rt = 0;
			String groupId = form.getGroupId();
	    	if (groupId != null && !groupId.isEmpty()) {
				// グループ削除（無効）
	    		rt = authGroupSetService.invalidGroup(groupId);
	    	}

	    	if (rt <= 0) {
				String msg = ms.getMessage("MSTO0006M0004", new String[] { groupId }, null);
				form.setErrMessage(msg);

				LogService.info("グループ設定画面", "AuthGroupSetController", "グループ設定画面削除処理(0件削除)", "警告");
			} else {
				// 画面クリア
				resetFormSearch(form);
				// 完了メッセージ
				String msg = ms.getMessage("CMN0003", new String[] { "グループ削除" }, null);
				model.addAttribute("axioMessage", msg);
			}

		} catch (Exception e) {
			LogService.system("グループ設定画面処理", "AuthGroupSetController", "削除処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			String msg = ms.getMessage("ERR001", null, null);
			form.setErrMessage(msg);
			LogService.info("グループ設定画面処理", "AuthGroupSetController", "削除処理", "··異常終了");
			return modelAndView;
		} finally {
			modelAndView.addObject("AuthGroupSetForm", form);
			modelAndView.setViewName(OWN_PAGE);
		}

		//新しいトーケン設定
		saveAccessToken(form);

		LogService.info("グループ設定画面処理", "AuthGroupSetController", "削除処理", "正常終了");
    	return modelAndView;
	}

	/**
	 * クリア処理
	 *
	 * @throws Exception
	 *
	 */
	@RequestMapping("/authGroupSetClear")
	public ModelAndView clear(@ModelAttribute("AuthGroupSetForm") AuthGroupSetForm form, BindingResult result, HttpServletRequest request)  {
		LogService.info("グループ設定画面処理", "AuthGroupSetController", "クリア処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

		// 画面クリア
		resetFormSearch(form);

		modelAndView.addObject("AuthGroupSetForm", form);
		modelAndView.setViewName(REDIRECT_PAGE);

		LogService.info("グループ設定画面処理", "AuthGroupSetController", "クリア処理", "正常終了");
		return modelAndView;
	}


	/**
	 * formの情報を初期化する。
	 *
	 * @param form
	 * @return form
	 */
	private AuthGroupSetForm resetFormSearch(AuthGroupSetForm form) {
		form.setGroupId(null);
		form.setGroupDetail(null);

		//デフォルート開始日、終了日設定
		form.setGroupStartDate(new SimpleDateFormat("yyyy/MM/dd").format(new Date()));
		form.setGroupEndDate("2999/12/31");

		form.setGroupNameEn(null);
		form.setGroupNameJp(null);
		form.setGroupRuleList(null);

		//制御フラグをクリア
		form.setChangedFlg("");
		form.setEditFlg("");

		//モダール画面連携項目をクリア
		form.setReflectFunction("");
		form.setParamVal("");

		return form;
	}

    /**
     * メタからの日付を変換する
     *
     * @param sDate
     * @param itemName
     * @return
     * @throws ParseException
     */
	private Date convDate (String sDate, String itemName ) throws Exception {

		SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd");
		sdf.setLenient(false);
		Date formatDate = null;

		try {
			if (sDate != null && !sDate.isEmpty()) {
			    // Date型変換
			    formatDate = sdf.parse(sDate);
			}
		}
		catch (Exception e) {
        	String msg = ms.getMessage("MSTO0006M0005", new String[] {itemName, e.getMessage()}, null);
        	Exception ex = new Exception(msg);
        	throw ex;
		}
		return formatDate;
	}


    /**
     * 引数に対して前0補完する（指定桁数分）
     *
     * @param str 変換対象文字列
     * @return String 0補完後の文字列
     */
    private String buriesZero(String str, int outStrLeng) {

        String inStr = "";
        if (str != null) {
        	inStr = str;
        }
        String outStr = "";
        String outZeroStr = "";
        int inStrLeng = inStr.length();
        int buriesCnt = outStrLeng - inStrLeng;

        if (inStrLeng < outStrLeng) {
            for (int i = 0; i < buriesCnt; i++) {
                outZeroStr += "0";
            }
            outStr = outZeroStr + inStr;
        } else {
            outStr = inStr;
        }

        return outStr;
    }

}
