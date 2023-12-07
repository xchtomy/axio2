/*
 * タイトル：汎用コードマスタ設定画面
 * 説明    ：汎用コードマスタ設定画面処理を行う。
 *
 * 会社名  ：JBD
 *
 */
package jp.co.axio.masterMentsetSystem.controller;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.GpuMasterSetForm.DeleteGroup;
import jp.co.axio.masterMentsetSystem.controller.GpuMasterSetForm.ReflectionGroup;
import jp.co.axio.masterMentsetSystem.controller.GpuMasterSetForm.SaveGroup;
import jp.co.axio.masterMentsetSystem.controller.GpuMasterSetForm.SearchGroup;
import jp.co.axio.masterMentsetSystem.controller.GpuMasterSetForm.SelectGroup;
import jp.co.axio.masterMentsetSystem.dto.CodeValueDto;
import jp.co.axio.masterMentsetSystem.dto.GpuMasterSetComparator;
import jp.co.axio.masterMentsetSystem.dto.GpuMasterSetDto;
import jp.co.axio.masterMentsetSystem.model.MgpCodeMst;
import jp.co.axio.masterMentsetSystem.service.GpuMasterSetService;

/**
 * 汎用コードマスタ設定画面処理
 *
 * @author JCBC
 * @version 1.0
 */
@Controller
public class GpuMasterSetController extends accessController {

	/** 自画面のHTMLテンプレート */
	private final String OWN_PAGE = "GpuMasterSet/gpuMasterSet";

    /** 初期ページ　*/
    private final String REDIRECT_PAGE = "redirect:./GpuMasterSet";

	/** 分類コードID */
	private final String classCodeId = "00000";

	/** 対象の分類選択 */
	private String selectClassCodeValue = "";

	/** 自処理対象画面名 */
	private static final String OWN_TITLE = "汎用コードマスタ設定画面";

	/** ログインコントローラ */
	@Autowired
	LoginController loginController;

    @Autowired
    HttpSession session;

	@Autowired
	GpuMasterSetService GpuMasterSetService;

    @Autowired
    MessageSource ms;

	/**
	 * 初期処理
	 *
	 * @throws Exception
	 *
	 */
	@RequestMapping("/GpuMasterSet")
	public ModelAndView index(RedirectAttributes redirectAttributes)  {
		LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "初期処理", "開始");

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

		GpuMasterSetForm form = new GpuMasterSetForm();
		resetValue(form);

		//アクセストークン設定 二重送信防止
		saveAccessToken(form);

		session.removeAttribute("selectClassCodeList");
		session.removeAttribute("classCodeValueList");
	    try {

			form.setGpCodeSearchList(GpuMasterSetService.selectMgpCodeMstSearch());
	    	form.setClassCodeId(form.getGpCodeSearchList().get(0).getCodeValue());
			List<CodeValueDto> classCodeSearchResultList;

            classCodeSearchResultList = GpuMasterSetService.selectValueSearch(form.getGpCodeSearchList().get(0).getCodeValue());
    		form.setClassCodeValueList(classCodeSearchResultList);
    		session.setAttribute("classCodeValueList", classCodeSearchResultList);
    		selectClassCodeValue = classCodeSearchResultList.get(0).getCodeValue();
    		form.setSelectClassCodeValue(classCodeSearchResultList.get(0).getCodeValue());
    		form.setSelectClassCodeName(classCodeSearchResultList.get(0).getCodeName());
    		form.setTxtClassCode(classCodeSearchResultList.get(0).getCodeName());
    		List<GpuMasterSetDto> selectClassCodeList = GpuMasterSetService.selectMgpCodeMstSearchByGpuMasterSet(selectClassCodeValue,form.getClassCodeId());

		    List<GpuMasterSetDto>   selectClassCodeListSort = SelectClassCodeListSort(selectClassCodeList);
			session.setAttribute("selectClassCodeList", selectClassCodeListSort);
			form.setSelectClassCodeList(selectClassCodeListSort);
		} catch (Exception e) {
			LogService.system("汎用コードマスタ設定画面", "GpuMasterSetController", "分類コード名称リスト検索処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			modelAndView.addObject("GpuMasterSetForm", form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "初期処理", "··異常終了");
			return modelAndView;
		}

		modelAndView.addObject("GpuMasterSetForm", form);
		modelAndView.setViewName(OWN_PAGE);
		LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "初期処理", "正常終了");
		return modelAndView;

	}

	/**
	 * 分類リストに表示する。
	 *
	 * @param form   フォーム情報
	 * @param result バインド
	 * @param model  モデル
	 * @return 遷移先
	 * @throws Exception
	 */
	@RequestMapping(path = "/GpuMasterSetSearch", method = RequestMethod.POST)
	public String search(@ModelAttribute("GpuMasterSetForm")  @Validated(SearchGroup.class) GpuMasterSetForm form, BindingResult result) {
		LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "分類リスト検索処理", "開始");

		// フォーム情報を初期化
		resetFormSearch(form);
		setValue(form);

		try {

			// 項目属性チェック結果判定
			if (result.hasErrors()) {
				LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "分類リスト検索入力チェック", "異常終了");
				return OWN_PAGE;
			}

			session.removeAttribute("selectClassCodeList");
			// 分類コードIDで対象の分類を取得
			List<CodeValueDto> classCodeSearchResultList;

            classCodeSearchResultList = GpuMasterSetService.selectValueSearch(form.getClassCodeId());
    		form.setClassCodeValueList(classCodeSearchResultList);
    		session.setAttribute("classCodeValueList", classCodeSearchResultList);
			form.setSearchFlg("1");
    		selectClassCodeValue = classCodeSearchResultList.get(0).getCodeValue();
    		form.setSelectClassCodeValue(classCodeSearchResultList.get(0).getCodeValue());
    		form.setSelectClassCodeName(classCodeSearchResultList.get(0).getCodeName());
    		form.setTxtClassCode(classCodeSearchResultList.get(0).getCodeName());

			List<GpuMasterSetDto> selectClassCodeList = GpuMasterSetService.selectMgpCodeMstSearchByGpuMasterSet(selectClassCodeValue,form.getClassCodeId());

		    List<GpuMasterSetDto>   selectClassCodeListSort = SelectClassCodeListSort(selectClassCodeList);
			session.setAttribute("selectClassCodeList", selectClassCodeListSort);
			form.setSelectClassCodeList(selectClassCodeListSort);

		} catch (Exception e) {
			LogService.system("汎用コードマスタ設定画面", "GpuMasterSetController", "分類リスト検索処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "分類リスト検索処理", "異常終了");
			return OWN_PAGE;
		}
		LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "分類リスト検索処理", "正常終了");
		return OWN_PAGE;

	}

	/**
	 * 分類選択一覧で選択された分類のコードを取得する。
	 *
	 * @param form   フォーム情報
	 * @param result バインド
	 * @param model  モデル
	 * @return 遷移先
	 * @throws Exception
	 */
	@RequestMapping("/GpuMasterSetSelect")
	public ModelAndView select(@ModelAttribute("GpuMasterSetForm") @Validated(SelectGroup.class) GpuMasterSetForm form, BindingResult result)  {

		LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "分類一覧検索処理開始", "");
		setValue(form);
		ModelAndView modelAndView = new ModelAndView();
		selectClassCodeValue = form.getSelectClassCodeValue();
		form.setClassCodeValueList(castList2(freshAttribute(form, "classCodeValueList")));
		// 対象の分類コードを取得
		List<GpuMasterSetDto> selectClassCodeList;

		try {
			selectClassCodeList = GpuMasterSetService.selectMgpCodeMstSearchByGpuMasterSet(selectClassCodeValue,form.getClassCodeId());

		    List<GpuMasterSetDto>   selectClassCodeListSort = SelectClassCodeListSort(selectClassCodeList);
			session.setAttribute("selectClassCodeList", selectClassCodeListSort);
			form.setSelectClassCodeList(selectClassCodeListSort);

		} catch (Exception e) {
			LogService.system("汎用コードマスタ設定画面", "GpuMasterSetController", "分類コード名称リスト検索処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			modelAndView.addObject("GpuMasterSetForm", form);
			modelAndView.setViewName(OWN_PAGE);
			LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "分類コード名称リスト検索処理", "··異常終了");
			return modelAndView;
		}

		form.setTxtClassCode(form.getSelectClassCodeName());
		form.setSelectFlg("1");
		resetFormSelect(form);
		LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "分類一覧検索処理正常終了", "");

		modelAndView.addObject("GpuMasterSetForm", form);
		modelAndView.setViewName(OWN_PAGE);
		return modelAndView;
	}
	/**
	 * コードリストで変更したデータをDBに反映する。
	 *
	 * @param form   フォーム情報
	 * @param result バインド
	 * @param model  モデル
	 * @return 遷移先
	 * @throws Exception
	 */
	@RequestMapping("/GpuMasterSetSave")
	public String save(@ModelAttribute("GpuMasterSetForm") @Validated(SaveGroup.class) GpuMasterSetForm form, BindingResult result, Model model){

		LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "保存処理", "開始");

		//二重送信防止
		if (!checkAccessToken(form)) {
			return REDIRECT_PAGE;
		}

		setValue(form);
		form.setClassCodeValueList(castList2(freshAttribute(form, "classCodeValueList")));

		// DB反映処理
		// セッションからコードリストを取得
		List<GpuMasterSetDto> selectClassCodeList = castList1(freshAttribute(form, "selectClassCodeList"));

		Boolean checkflg = false;
		if (form.getClassCodeId().equals(classCodeId)) {
			for (GpuMasterSetDto updateDto : selectClassCodeList) {
				if (updateDto.codeValue.equals(classCodeId)) {
					checkflg = true;
					break;
				}
			}
		} else {
			checkflg = true;
		}

		if (!checkflg) {
			form.setSelectClassCodeList(selectClassCodeList);
			String msg = ms.getMessage("CMN0007", new String[] { classCodeId }, null);
			result.reject("", msg); // エラーメッセージ表示
			LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "保存処理関連チェック", "異常終了");
			return OWN_PAGE;

		}

		try {

			GpuMasterSetService.saveData(form, selectClassCodeList);

			// 対象の分類コードを取得
			List<GpuMasterSetDto> classCodeList;
			classCodeList = GpuMasterSetService.selectMgpCodeMstSearchByGpuMasterSet(selectClassCodeValue,form.getClassCodeId());

		    List<GpuMasterSetDto>   selectClassCodeListSort = SelectClassCodeListSort(classCodeList);
			session.setAttribute("selectClassCodeList", selectClassCodeListSort);
			form.setSelectClassCodeList(selectClassCodeListSort);

			// 分類コードIDで対象の分類を取得
			List<CodeValueDto>  classCodeSearchResultList = GpuMasterSetService.selectValueSearch(form.getClassCodeId());
    		form.setClassCodeValueList(classCodeSearchResultList);
    		session.setAttribute("classCodeValueList", classCodeSearchResultList);
			setValue(form);
			// 完了メッセージ
	        String msg = ms.getMessage("CMN0003", new String[] { "保存" }, null);
			model.addAttribute("axioMessage", msg);
		} catch (SQLException e) {
			LogService.system("汎用コードマスタ設定画面", "GpuMasterSetController", "保存処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setSelectClassCodeList(castList1(freshAttribute(form,"selectClassCodeList")));
            result.reject("", e.getMessage()); // エラーメッセージ表示
			LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "保存処理", "異常終了");
			return OWN_PAGE;
		} catch (Exception e) {
			LogService.system("汎用コードマスタ設定画面", "GpuMasterSetController", "保存処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			form.setSelectClassCodeList(castList1(freshAttribute(form, "selectClassCodeList")));
			LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "保存処理", "異常終了");
			return OWN_PAGE;
		}

		form.setEditFlg("");
		form.setChangedDataFlg("");

        //新しいアクセストークン設定
        saveAccessToken(form);

		LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "登録処理", "正常終了");
		return OWN_PAGE;

	}

	/**
	 * 値選択一覧の内容をコードリストに反映する。
	 *
	 * @param form   フォーム情報
	 * @param result バインド
	 * @param model  モデル
	 * @return 遷移先
	 */
	@RequestMapping("/GpuMasterSetReflection")
	public String reflection(@ModelAttribute("GpuMasterSetForm") @Validated(ReflectionGroup.class) GpuMasterSetForm form, BindingResult result) {

		LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "値選択一覧の内容をコードリストに反映処理開始", "");

		//二重送信、ページ不正アクセス防止
		if (!checkAccessToken(form)) {
			return REDIRECT_PAGE;
		}

		setValue(form);
		form.setClassCodeValueList(castList2(freshAttribute(form, "classCodeValueList")));

			// 項目属性チェック結果判定
			if (result.hasErrors()) {
				form.setSelectClassCodeList(castList1(freshAttribute(form, "selectClassCodeList")));
				LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "値選択一覧の内容をコードリストに反映チェック処理", "NG");
				return OWN_PAGE;
			}

			//関連チェック

			if (form.getClassCodeId().equals("00000")) {
				if (GpuMasterSetService.codeValueCheck(form.getClassCodeNo(),form.getClassCodeValue())) {
					form.setSelectClassCodeList(castList1(freshAttribute(form, "selectClassCodeList")));
					//Integer index= new Integer(form.getClassCodeValue()) -1;
					Integer index = Integer.parseInt(form.getClassCodeValue()) - 1;

					StringBuilder parms = new StringBuilder();
					parms.append("値種別について、「VALUE_") ;
					parms.append(index.toString());
					parms.append("」が登録されない（値がNULL）場合、「VALUE_");
					parms.append(form.getClassCodeValue());
					parms.append("」の登録が不可、先ずは「VALUE_");
					parms.append(index.toString());
					parms.append("」が登録してください。");
					String msg = parms.toString();
//			        String msg = ms.getMessage("CMN0004", new String[] { parms.toString() } , null);
		            result.reject("", msg); // エラーメッセージ表示
					LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "値選択一覧の内容をコードリストに反映チェック処理", "NG");
					return OWN_PAGE;
				}
			}

			Boolean insertflg = true;

			List<GpuMasterSetDto> selectClassCodeList = castList1(freshAttribute(form, "selectClassCodeList"));
			String selectClassCodeNo = form.getClassCodeNo();
			for (GpuMasterSetDto updateDto : selectClassCodeList) {
				if (updateDto.codeValue.equals(selectClassCodeNo)) {
					updateDto.gpCodeMstName = form.getClassCodeName();
					updateDto.setValue(form.getClassCodeDetail());

					updateDto.dispOrder = form.getClassCodeOrder();
					if (StringUtils.isEmpty(updateDto.editClass)) {
						updateDto.editClass = "2";
					insertflg = false;
					}
				}
			}
			// データがない場合：新規登録処理
			if (insertflg) {

				GpuMasterSetDto insertList = new GpuMasterSetDto();
				insertList.classCode = form.getClassCodeId();
				insertList.codeValue = selectClassCodeNo;
				insertList.gpCodeMstName = form.getClassCodeName();
				insertList.setValue(form.getClassCodeDetail());

				// 表示順が入力されていない場合は、値を設定する。
				if (StringUtils.isEmpty(form.getClassCodeOrder())) {
					insertList.dispOrder = "";
				} else {
					insertList.dispOrder = form.getClassCodeOrder();
				}

				insertList.editClass = "1";
				boolean cf = false;
				for(GpuMasterSetDto e : selectClassCodeList) {
					if (StringUtils.equals(e.classCode,insertList.classCode)
							&& StringUtils.equals(e.codeValue,insertList.codeValue )) {
						cf = true;
						e.gpCodeMstName = insertList.gpCodeMstName;
						e.value = insertList.value;
						e.dispOrder = insertList.dispOrder;
						break;
					}
				}
				if (!cf) {
					selectClassCodeList.add(insertList);
				}
			}
			// コードリストのソートを行う
			selectClassCodeList = SelectClassCodeListSort(selectClassCodeList);
			session.setAttribute("selectClassCodeList", selectClassCodeList);
			form.setSelectClassCodeList(selectClassCodeList);

			form.setEditFlg("1");
		resetFormReflection(form);
		LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "値選択一覧の内容をコードリストに反映処理", "正常終了");
		return OWN_PAGE;

	}

	/**
	 * 値選択一覧のコードリストから対象の分類を削除する。
	 *
	 * @param form   フォーム情報
	 * @param result バインド
	 * @param model  モデル
	 * @return 遷移先
	 */
	@RequestMapping("/GpuMasterSetDelete")
	public String delete(@ModelAttribute("GpuMasterSetForm") @Validated(DeleteGroup.class) GpuMasterSetForm form , BindingResult result) {

		LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "値選択一覧のコードリストから対象の分類を削除処理開始", "");

		//二重送信、ページ不正アクセス防止
		if (!checkAccessToken(form)) {
			return REDIRECT_PAGE;
		}

		form.setClassCodeValueList(castList2(freshAttribute(form, "classCodeValueList")));
		List<GpuMasterSetDto> selectClassCodeList = castList1(freshAttribute(form, "selectClassCodeList"));
		// 項目属性チェック結果判定
		if (result.hasErrors()) {
			form.setSelectClassCodeList(selectClassCodeList);
			LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "値選択一覧の内容をコードリストに反映チェック処理", "NG");
			return OWN_PAGE;
		}

		String maxClassCode = "";
		String listMaxClassCode = "";
		for (String deleteClassCodeNo : form.getCheckClassCode()) {
			for (GpuMasterSetDto deleteDto : selectClassCodeList) {
				listMaxClassCode = deleteDto.codeValue;
				if (maxClassCode.compareTo(listMaxClassCode) < 0) {
					maxClassCode = listMaxClassCode;
				}
				if (deleteDto.codeValue.equals(deleteClassCodeNo)) {
					deleteDto.editClass = "3";
				}
			}
		}

		session.setAttribute("selectClassCodeList", selectClassCodeList);
		form.setSelectClassCodeList(selectClassCodeList);
		form.setEditFlg("1");
		resetFormDelete(form);
			setValue(form);

		LogService.info("汎用コードマスタ設定画面", "GpuMasterSetController", "値選択一覧のコードリストから対象の分類を削除処理", "正常終了");
		return OWN_PAGE;
	}

	/**
	 * formの情報を取得し、設定する。
	 *
	 * @param form
	 * @return form
	 * @throws Exception
	 */
	private GpuMasterSetForm setValue(GpuMasterSetForm form)  {
		form.setGpCodeSearchList(GpuMasterSetService.selectMgpCodeMstSearch());
		form.setEditFlg(form.getEditFlg());
		return form;
	}

	/**
	 * formの情報を初期化する。
	 *
	 * @param form
	 * @return form
	 */
	private GpuMasterSetForm resetValue(GpuMasterSetForm form) {
		form.setClassCodeId("");
		form.setGpCodeSearchList(new ArrayList<MgpCodeMst>());
		form.setSelectClassCode("");

		form.setClassCodeValue("");
		List<CodeValueDto> codeValueDtoList = new ArrayList<CodeValueDto>();
		form.setClassCodeValueList(codeValueDtoList);
		form.setSelectClassCodeValue("");
		form.setSelectClassCodeName("");
		form.setSelectClassCodeList(new ArrayList<GpuMasterSetDto>());
		form.setTxtClassCode("");
		form.setClassCodeNo("");
		form.setClassCodeName("");
		form.setClassCodeDetail("");
		form.setClassCodeOrder("");
		form.setSelectClassName("");
		form.setEditFlg("");
		form.setSearchFlg("");
		form.setSelectFlg("");
		form.setDeleteClassCodeNo("");
		form.setClassCodeCheck(new ArrayList<String>());
		return form;
	}

	/**
	 * 検索時のformの情報を初期化する。
	 *
	 * @param form
	 * @return form
	 */
	private GpuMasterSetForm resetFormSearch(GpuMasterSetForm form) {
		List<CodeValueDto> codeValueDtoList = new ArrayList<CodeValueDto>();
		form.setClassCodeValueList(codeValueDtoList);

		form.setSelectClassCodeValue("");
		form.setSelectClassCodeName("");
		form.setClassCodeNo("");
		form.setClassCodeName("");
		form.setClassCodeDetail("");
		form.setClassCodeOrder("");
		form.setEditFlg("");
		form.setSearchFlg("");
		form.setSelectFlg("");
		return form;
	}

	/**
	 * 反映時のformの情報を初期化する。
	 *
	 * @param form
	 * @return form
	 */
	private GpuMasterSetForm resetFormSelect(GpuMasterSetForm form) {
		form.setClassCodeNo("");
		form.setClassCodeName("");
		form.setClassCodeDetail("");
		form.setClassCodeOrder("");
		form.setEditFlg("");
		return form;
	}

	/**
	 * 反映時のformの情報を初期化する。
	 *
	 * @param form
	 * @return form
	 */
	private GpuMasterSetForm resetFormDelete(GpuMasterSetForm form) {
		form.setClassCodeNo("");
		form.setClassCodeName("");
		form.setClassCodeDetail("");
		form.setClassCodeOrder("");
		return form;
	}

    /**
     * 反映時のformの情報を初期化する。
     *
     * @param form
     * @return form
     */
    private GpuMasterSetForm resetFormReflection(GpuMasterSetForm form) {
	form.setClassCodeNo("");
	form.setClassCodeName("");
	form.setClassCodeDetail("");
	form.setClassCodeOrder("");
    	return form;
    }

	/**
	 * コードリストを表示順でソートする。
	 *
	 * @param selectClassCodeList
	 * @return selectClassCodeList
	 */
	public List<GpuMasterSetDto> SelectClassCodeListSort(List<GpuMasterSetDto> selectClassCodeList) {
		Collections.sort(selectClassCodeList, new GpuMasterSetComparator());
		return selectClassCodeList;
	}

	/**
	 * sessionオブジェクトをListにキャストする。
	 *
	 * @param Object
	 * @return List
	 */
	@SuppressWarnings("unchecked")
	private List<GpuMasterSetDto> castList1(Object obj) {
		List<GpuMasterSetDto> GpuMasterSetList = (List<GpuMasterSetDto>) obj;
		return GpuMasterSetList;
	}

	/**
	 * sessionオブジェクトをListにキャストする。
	 *
	 * @param Object
	 * @return List
	 */
	@SuppressWarnings("unchecked")
	private List<CodeValueDto> castList2(Object obj) {
		List<CodeValueDto> codeValueList = (List<CodeValueDto>) obj;
		return codeValueList;
	}

	private Object freshAttribute(GpuMasterSetForm form, String s) {
		return session.getAttribute(s);
//		Object obj = session.getAttribute(s);
//		if (obj == null) {
//			LogService.debug("汎用コードマスタ設定画面", "GpuMasterSetController", "session.getAttribute([" + s + "])", "値がNULL");
//			if ("classCodeValueList".equalsIgnoreCase(s)) {
//				session.setAttribute("classCodeValueList", form.getClassCodeValueList());
//				return form.getClassCodeValueList();
//			} else {
//				session.setAttribute("selectClassCodeList", form.getSelectClassCodeList());
//				return form.getSelectClassCodeList();
//			}
//		} else {
//			return obj;
//		}
	}
}