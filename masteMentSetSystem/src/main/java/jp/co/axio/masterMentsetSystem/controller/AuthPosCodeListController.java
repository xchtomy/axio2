package jp.co.axio.masterMentsetSystem.controller;


import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import jp.co.axio.masterMentsetSystem.common.CheckDateFormat;
import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.AuthPosCodeListForm.SearchGroup;
import jp.co.axio.masterMentsetSystem.dto.AuthOrgCodeListDto;
import jp.co.axio.masterMentsetSystem.dto.AuthPosCodeListDto;
import jp.co.axio.masterMentsetSystem.service.AuthPosCodeListService;

/**
 * 役職コード一覧画面
 *
 * @author axio
 * @version 1.0
 */
@Controller
public class AuthPosCodeListController {

    /** 自画面のHTMLテンプレート */
    private static final String OWN_PAGE = "AuthCodeList/authPosCodeList";

    /** 自画面のタイトル */
    public static final String OWN_TITLE = "役職コード一覧画面";

    /** パラメータcallParameterに格納されているデータのキー（会社コード） */
	public static final String CALL_PARAMETER_DATA_KEY1 = "companyCode";

    /** パラメータcallParameterに格納されているデータのキー（役職コード） */
    public static final String CALL_PARAMETER_DATA_KEY2 = "positionCode";

	@Autowired
	AuthPosCodeListService authPosCodeListService;

    @Autowired
    MessageSource ms;

    @Autowired
	HttpSession session;

	/**
	 * 初期処理。
	 *
	 * @param requestParams - リクエストパラメータ（Map <String, String>）
	 * @return ModelAndView
	 */
	@RequestMapping("/authPosCodeList")
    public ModelAndView index(@RequestParam Map <String, String> requestParams) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "初期処理", "開始");
		ModelAndView modelAndView = new ModelAndView();

		AuthPosCodeListForm form = new AuthPosCodeListForm();
		resetValue(form);
		if (requestParams != null) {
			if (requestParams.containsKey("callForm")) {
				if (requestParams.get("callForm") != null) form.setCallForm(requestParams.get("callForm"));
			}
			if (requestParams.containsKey("callParameter")) {
				if (requestParams.get("callParameter") != null) form.setCallParameter(requestParams.get("callParameter"));
			}
			if (requestParams.containsKey("callReturn")) {
				if (requestParams.get("callReturn") != null) form.setCallReturn(requestParams.get("callReturn"));
			}
		}

		// セッションのクリア
		session.removeAttribute(this.getClass().getSimpleName() + ".searchResultList");

		//デフォルート有効基準日をセット
		form.setSearchStartDateYmd(new SimpleDateFormat("yyyy/MM/dd").format(new Date()));

		// 検索
	    try {
			List<Map<String,String>> selectedCodeMapList = decodeJson(form.getCallParameter());
			List<AuthPosCodeListDto> list = authPosCodeListService.selectMPosition(selectedCodeMapList
																					, selectedCodeMapList
																					, false
																					, form.getSearchCompanyCode()
																					, form.getSearchPositionCode()
																					, form.getSearchPositionName()
																					, form.getSearchStartDateYmd()
																					, form.getSearchEndDateYmd());
			session.setAttribute(this.getClass().getSimpleName() + ".searchResultList", list);
	    	form.setSearchResultList(list);
		} catch (Exception e) {
			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "組織情報検索処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			modelAndView.addObject(form.getClass().getSimpleName(), form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "初期処理", "異常終了");
			return modelAndView;
		}

	    modelAndView.addObject(form.getClass().getSimpleName(), form);
		modelAndView.setViewName(OWN_PAGE);
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "初期処理", "正常終了");

		return modelAndView;
	}

	/**
	 * 検索処理。
	 *
	 * @param form - フォーム情報（AuthPosCodeListForm）
	 * @param requestParams - リクエストパラメータ（Map <String, String>）
	 * @param result - バインド結果（BindingResult）
	 * @return 遷移先（String）
	 */
	@RequestMapping(path = "/authPosCodeListSearch", method = RequestMethod.POST)
	public String search(@ModelAttribute("AuthPosCodeListForm")  @Validated(SearchGroup.class) AuthPosCodeListForm form, @RequestParam Map <String, String> requestParams, BindingResult result) {
		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "検索処理", "開始");
		form.setSearchResultList(extractedSearchResultList());
		form.setErrMessage(null);

		//入力日付のフォーマットチェック
		if (!CheckDateFormat.checkDateYMD(form.getSearchStartDateYmd())) {

			List<AuthPosCodeListDto> list = new ArrayList<AuthPosCodeListDto>();
			form.setSearchResultList(list);
			form.setErrMessage(ms.getMessage("CMN0008", null, null));
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "検索処理", "正常終了");
			return OWN_PAGE;
		}

		// 検索
	    try {
			List<Map<String,String>> selectedCodeMapList = decodeJson(form.getCallParameter());
			List<Map<String,String>> checkedCodeMapList = decodeJson(form.getCheckedCodes());
			List<AuthPosCodeListDto> list = authPosCodeListService.selectMPosition(selectedCodeMapList
																					, checkedCodeMapList
																					, true
																					, form.getSearchCompanyCode()
																					, form.getSearchPositionCode()
																					, form.getSearchPositionName()
																					, form.getSearchStartDateYmd()
																					, form.getSearchEndDateYmd());
	    	int ocnt = selectedCodeMapList==null?0:selectedCodeMapList.size();
	    	int scnt = list==null?0:list.size();
	    	if (scnt<=0) {
	    		//Data not found
	    		form.setErrMessage(ms.getMessage("MSTO0008M0001", null, null));
	    	} else if (scnt <= ocnt) {
	    		form.setErrMessage(ms.getMessage("MSTO0008M0002", null, null));
	    	}
			session.setAttribute(this.getClass().getSimpleName() + ".searchResultList", list);
			form.setSearchResultList(list);
		} catch (Exception e) {
			LogService.system(OWN_TITLE, this.getClass().getSimpleName(), "組織情報検索処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setErrMessage(ms.getMessage("ERR001", null, null));
			LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "検索処理", "異常終了");
			return OWN_PAGE;
		}

		LogService.info(OWN_TITLE, this.getClass().getSimpleName(), "検索処理", "正常終了");
		return OWN_PAGE;

	}

	/**
	 * セッション情報に保持した検索結果一覧を抽出する。
	 *
	 * @return 検索結果一覧（List<AuthPosCodeListDto>）
	 */
	@SuppressWarnings("unchecked")
	private List<AuthPosCodeListDto> extractedSearchResultList() {
		List<AuthPosCodeListDto> list = null;
		try {
			if (session != null) {
				list = (List<AuthPosCodeListDto>) session.getAttribute(this.getClass().getSimpleName() + ".searchResultList");
			}

		} catch (ClassCastException e) {
		}
		if (list == null) list = new ArrayList<AuthPosCodeListDto>();

		return list;
	}

	/**
	 * フォーム情報を初期化する。
	 *
	 * @param form - フォーム情報（AuthPosCodeListForm）
	 */
	private void resetValue(AuthPosCodeListForm form) {
		form.setCallForm("");
		form.setCallParameter("");
		form.setCallReturn("");
		form.setCheckedCodes("");
		form.setSearchStartDateYmd("");
		form.setSearchEndDateYmd("");
		form.setSearchCompanyCode("");
		form.setSearchPositionCode("");
		form.setSearchPositionName("");
		form.setSearchResultList(new ArrayList<AuthPosCodeListDto>());
		form.setErrMessage(null);
	}

	/**
	 * JSON文字列をList<Map<String, String>>に変換する。
	 *
	 * @param jsonString - JSON文字列（String）
	 * @return List<Map<String, String>>
	 * @throws JsonMappingException
	 * @throws JsonProcessingException
	 */
	private List<Map<String, String>> decodeJson(String jsonString) throws JsonMappingException, JsonProcessingException {
		List<Map<String, String>> result = new ArrayList<Map<String, String>>();

		if (jsonString != null && jsonString.length() > 0) {
			try {
				ObjectMapper mapper = new ObjectMapper();
				result = mapper.readValue(jsonString, new TypeReference<List<Map<String, String>>>(){});
			} catch (JsonMappingException e) {
				throw e;
			} catch (JsonProcessingException e) {
				throw e;
			}
		}

		return result;
	}
}
