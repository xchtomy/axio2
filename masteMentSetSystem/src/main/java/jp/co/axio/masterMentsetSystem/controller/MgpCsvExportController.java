/*
 * タイトル：汎用CSV設定画面
 * 説明    ：汎用CSV設定画面処理を行う。
 *
 * 会社名  ：axio
 *
 */
package jp.co.axio.masterMentsetSystem.controller;

import java.io.UnsupportedEncodingException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.MgpCsvExportForm.saveGroup;
import jp.co.axio.masterMentsetSystem.controller.MgpCsvExportForm.testRunGroup;
import jp.co.axio.masterMentsetSystem.dto.CodeValueDto;
import jp.co.axio.masterMentsetSystem.dto.TargetViewInfoResultListDto;
import jp.co.axio.masterMentsetSystem.model.MgpCsvExportDefInfo;
import jp.co.axio.masterMentsetSystem.service.MgpCsvExportService;


/**
 * 汎用CSV設定画面処理
 *
 * @author JCBC
 * @version 1.0
 */
@Controller
public class MgpCsvExportController extends accessController {

    /** 自画面のHTMLテンプレート */
    private final String OWN_PAGE = "MgpCsvExport/mgpCsvExport";

    /** 初期ページ　*/
    private final String REDIRECT_PAGE = "redirect:./mgpCsvExport";

	/** 自処理対象画面名 */
	private static final String OWN_TITLE = "グループ一覧画面";

	/** ログインコントローラ */
	@Autowired
	LoginController loginController;

    @Autowired
    MgpCsvExportService mgpCsvExportService;

    @Autowired
    MessageSource ms;

    @Value("${config.character.codeValue}")
    private String codeValue;

    @Value("${config.character.codeName}")
    private String codeName;

    @Value("${config.parent.file.path}")
    private String parentFilePath;

    /**
            * 初期処理
     *
     * @return 処理結果データ
     *
     */
    @RequestMapping("/mgpCsvExport")
    public String index(@ModelAttribute("mgpCsvExportForm") MgpCsvExportForm form, BindingResult result, HttpServletRequest request, RedirectAttributes redirectAttributes) {

		LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "初期処理", "開始");

		/**
		 * 2022/02/07　ログインチェック追加 開始
		 */
		// 既存処理コメントアウト
		// ModelAndView modelAndView = new ModelAndView();

		ModelAndView modelAndView = loginController.checkLogin(OWN_TITLE, redirectAttributes);
		if (modelAndView != null) {
			// return modelAndView;// ログイン画面へ遷移
			return modelAndView.getViewName();
		} else {
			// 2022/06/22　権限チェック追加
			modelAndView = loginController.checkAdmin(OWN_TITLE, redirectAttributes);
			if (modelAndView != null) {
				return modelAndView.getViewName();// ログイン画面へ遷移
			}

			// modelAndView = new ModelAndView();
		}
		/**
		 * 2022/02/07　ログインチェック追加 終了
		 */
		//アクセストークン設定 二重送信防止

		saveAccessToken(form);

		resetFormSearch(form);
	    try {
	    	form.setCharCodeList(strCodeListGet());
			form.setMgpCsvExportList(mgpCsvExportService.selectMgpCsvExportSearch());
			form.setMstExportList(mgpCsvExportService.selectMstExportSearch());
		} catch (Exception e) {
			LogService.system("汎用CSV設定画面処理", "MgpCsvExportController", "初期処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "初期処理", "··異常終了");
			return OWN_PAGE;
		}
		LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "初期処理", "正常終了");
    	return OWN_PAGE;
    }

    /**
    *CSVファイル情報選択時更新取得処理
	*
	* @return 処理結果データ
	*
	*/
	@RequestMapping("/mgpCsvExportSelectCsvFiledata")
	public String selectCsvFiledata(@ModelAttribute("mgpCsvExportForm") @Validated MgpCsvExportForm form, BindingResult result, HttpServletRequest request) {

	  LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "CSVファイル情報選択時更新取得処理", "開始");

		try {
	    	form.setCharCodeList(strCodeListGet());
			form.setMgpCsvExportList(mgpCsvExportService.selectMgpCsvExportSearch());
			form.setMstExportList(mgpCsvExportService.selectMstExportSearch());

			if(StringUtils.isEmpty(form.getSelectClassCode())) {
				resetFormSearch(form);
				LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "CSVファイル情報選択時更新取得処理", "正常終了");
				return OWN_PAGE;
			}

			MgpCsvExportDefInfo mgpCsvExportDefInfo  = mgpCsvExportService.selectCsvFiledata(new Integer(form.getSelectClassCode()));
			if (mgpCsvExportDefInfo !=null) {
				form.setSqlNo(mgpCsvExportDefInfo.getSqlNo());
				form.setSystemId(mgpCsvExportDefInfo.getSystemId());
				form.setSqlRegisterName(mgpCsvExportDefInfo.getSqlRegisterName());
				form.setValidFlag(mgpCsvExportDefInfo.getValidFlag());
				form.setParentFilePath(parentFilePath);
				form.setSubFilePath(StringUtils.replace(mgpCsvExportDefInfo.getFileSavePath(), parentFilePath, ""));

				form.setFileName(mgpCsvExportDefInfo.getFileName());
				form.setFileClass(mgpCsvExportDefInfo.getFileClass());
				form.setFileNamingClass(mgpCsvExportDefInfo.getFileNamingClass());
				form.setStrCode(mgpCsvExportDefInfo.getStrCode());
				form.setDelimiterClass(mgpCsvExportDefInfo.getDelimiterClass());
				form.setFileCodeFormatClass(mgpCsvExportDefInfo.getFileCodeFormatClass());
				form.setSeparationDefClass(mgpCsvExportDefInfo.getSeparationDefClass());
				form.setFileHeaderInfoClass(mgpCsvExportDefInfo.getFileHeaderInfoClass());
				form.setSqlOutTableName(mgpCsvExportDefInfo.getSqlOutTableName());
				form.setSqlOutTableNameBak(mgpCsvExportDefInfo.getSqlOutTableName());
				form.setSqlOutData(mgpCsvExportDefInfo.getSqlOutData());

				form.setSqlColumnDef(mgpCsvExportDefInfo.getSqlColumnDef());
				form.setSqlWhereDef(mgpCsvExportDefInfo.getSqlWhereDef());
				form.setVersionNumber(mgpCsvExportDefInfo.getVersionNumber());

		        String tableName=  StringUtils.lowerCase(mgpCsvExportDefInfo.getSqlOutTableName());
				form.setTargetViewInfoList(mgpCsvExportService.selectTargetViewInfoSearchResult(tableName));
			    form.setTargetViewOutList(targetView(mgpCsvExportDefInfo.getSqlColumnDef()));

			    form.setSqlInputDataTxt(refTargetItemList(mgpCsvExportDefInfo.getSqlColumnDef()));

			    form.setEditFlg("2");
			}


		} catch (Exception e) {
			LogService.system("汎用CSV設定画面処理", "MgpCsvExportController", "CSVファイル情報選択時更新取得処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "CSVファイル情報選択時更新取得処理", "··異常終了");
			return OWN_PAGE;
		}
		LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "CSVファイル情報選択時更新取得処理", "正常終了");
		return OWN_PAGE;
	}

    /**
     *　出力対象選択時処理
     *
     * @return 処理結果データ
     *
     */
    @RequestMapping("/mgpCsvExport/redraw")
    @ResponseBody
    public MgpCsvExportForm redraw(@ModelAttribute("mgpCsvExportForm") @Validated MgpCsvExportForm form, BindingResult result, HttpServletRequest request) {

		LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "出力対象選択時処理", "開始");

        String tableName=  StringUtils.lowerCase(form.getSqlOutTableName());
    	try {
			form.setTargetViewInfoList(mgpCsvExportService.selectTargetViewInfoSearchResult(tableName));
		} catch (Exception e) {
			LogService.system("汎用CSV設定画面処理", "MgpCsvExportController", "出力対象選択時処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "出力対象選択時処理", "··異常終了");
			return form;
		}
		LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "出力対象選択時処理", "正常終了");
		return form;
    }

    /**
     * SQLチェックボタン押下処理
     *
     * @return 処理結果データ
     * @throws SQLException
     *
     */
    @RequestMapping("/mgpCsvExportSqlCheck")
    public String testRun(@ModelAttribute @Validated(testRunGroup.class) MgpCsvExportForm form, BindingResult result, HttpServletRequest request, Model model) throws SQLException {

		LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "SQLチェックボタン押下処理", "開始");
		form.setParentFilePath(parentFilePath);
	    try {
	    	form.setCharCodeList(strCodeListGet());
			form.setMgpCsvExportList(mgpCsvExportService.selectMgpCsvExportSearch());
			form.setMstExportList(mgpCsvExportService.selectMstExportSearch());
		} catch (Exception e) {
			LogService.system("汎用CSV設定画面処理", "MgpCsvExportController", "SQLチェックボタン押下処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "SQLチェックボタン押下処理", "··異常終了");
			return OWN_PAGE;
		}
	    //抽出元情報設定
	    form.setTargetViewInfoList(targetView(form.getSqlInfoData()));
        // 出力対象を設定
	    form.setTargetViewOutList(targetView(form.getSqlColumnDef()));

        if (result.hasErrors()) {
            return OWN_PAGE;
        }

        // 相関チェック

         Boolean checkFlag = false;
        //SQL文を定義する
        String sql = form.getSqlOutData();
        String where = form.getSqlWhereDef();
        if(StringUtils.isEmpty(form.getSqlColumnDef())){
            //例外発生時の処理
            String msg = ms.getMessage("MSTO0005M005", null, null);
            result.reject("",msg);
            checkFlag = true;
        }
        if((where.indexOf(";") != -1) || (where.indexOf("；") != -1)){
            //例外発生時の処理
            String msg = ms.getMessage("CMN0001", new String[] { "セミコロン" }, null);
            //result.rejectValue("sqlWhereDef", "", msg);
            result.reject("", msg);
            checkFlag = true;
        }

//        String wherelower=  StringUtils.lowerCase(where).replaceAll(" ", "");
//        if(wherelower.indexOf("where") == -1
//        		&& wherelower.indexOf("orderby") == -1
//        		&& wherelower.trim().length() > 0) {
//            // エラーメッセージ表示
//            String msg = ms.getMessage("CMN0002", new String[] { "「WHERE/ORDER BY」" }, null);
//            result.rejectValue("sqlWhereDef", "", msg);
//            checkFlag = true;
//        }

        //条件入力欄に先頭のキーワードがwhere/order by 以外の場合エラー
        String lwhere = StringUtils.lowerCase(where).trim();
        String chkRegex = "^(where|order by).*";
        Pattern chkPattern = Pattern.compile(chkRegex);
        Matcher mchk = chkPattern.matcher(lwhere);
        if (!mchk.find() && lwhere.length() > 0){
            // エラーメッセージ表示
            String msg = ms.getMessage("CMN0002", new String[] { "「WHERE/ORDER BY」" }, null);
            //result.rejectValue("sqlWhereDef", "", msg);
            result.reject("", msg);
            checkFlag = true;
        }

        if (checkFlag) {
			LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "SQLチェックボタン押下処理相関チェック", "異常終了");
            return OWN_PAGE;
        }

        String cnt = "0";
        try{

        	cnt = mgpCsvExportService.run(sql);

        }catch(Exception ex){
             //例外発生時の処理
            result.reject("", ex.getMessage()); // エラーメッセージ表示
			LogService.system("汎用CSV設定画面処理", "MgpCsvExportController", "SQLチェックボタン押下処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(ex));
			LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "SQLチェックボタン押下処理", "··異常終了");
            return OWN_PAGE;
        }

    	form.setSaveFlg("1");
        // 完了メッセージ
    	Object p[] = {cnt};
        String msg = ms.getMessage("MSTO0005M004",  p, null);
        model.addAttribute("axioMessage", msg);
		LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "SQLチェックボタン押下処理", "正常終了");
    	return OWN_PAGE;
    }

    /**
     * 登録ボタン押下処理
     *
     * @return 処理結果データ
     *
     */
    @RequestMapping("/mgpCsvExportSave")
    public String save(@ModelAttribute @Validated(saveGroup.class) MgpCsvExportForm form, BindingResult result, HttpServletRequest request, Model model) {
		LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "登録ボタン押下処理", "開始");

		//二重送信、ページ不正アクセス防止
		if (!checkAccessToken(form)) {
			return REDIRECT_PAGE;
		}

		form.setParentFilePath(parentFilePath);
	    try {
	    	form.setCharCodeList(strCodeListGet());
			form.setMgpCsvExportList(mgpCsvExportService.selectMgpCsvExportSearch());
			form.setMstExportList(mgpCsvExportService.selectMstExportSearch());
		} catch (Exception e) {
			LogService.system("汎用CSV設定画面処理", "MgpCsvExportController", "登録ボタン押下処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(e));
			LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "登録ボタン押下処理", "··異常終了");
			return OWN_PAGE;
		}
	    //抽出元情報設定
	    form.setTargetViewInfoList(targetView(form.getSqlInfoData()));
        // 出力対象を設定
	    form.setTargetViewOutList(targetView(form.getSqlColumnDef()));
        if (result.hasErrors()) {
            form.setSaveFlg("1");
            return OWN_PAGE;
        }
        // 相関チェック

        Boolean checkFlag = false;
       //SQL文を定義する
       String sql = form.getSqlOutData();
       String where = form.getSqlWhereDef();
       if(StringUtils.isEmpty(form.getSqlColumnDef())){
           //例外発生時の処理
           String msg = ms.getMessage("MSTO0005M005", null, null);
           result.reject("",msg);
           checkFlag = true;
       }

       if((where.indexOf(";") != -1) || (where.indexOf("；") != -1)){
           //例外発生時の処理
           String msg = ms.getMessage("CMN0001", new String[] { "セミコロン" }, null);
           //result.rejectValue("sqlWhereDef", "", msg);
           result.reject("", msg);
           checkFlag = true;
       }

       String wherelower=  StringUtils.lowerCase(where).replaceAll(" ", "");
//       if((wherelower.indexOf("where") == -1) || (wherelower.indexOf("where") == -1 )){
//           //例外発生時の処理
//           String msg = ms.getMessage("CMN0002", new String[] { "「WHERE」" }, null);
//           result.rejectValue("sqlWhereDef", "", msg);
//           checkFlag = true;
//       }
       if(wherelower.indexOf("where") == -1 && wherelower.indexOf("orderby") == -1 && wherelower.trim().length() > 0) {
           // エラーメッセージ表示
           String msg = ms.getMessage("CMN0002", new String[] { "「WHERE/ORDER BY」" }, null);
           //result.rejectValue("sqlWhereDef", "", msg);
           result.reject("", msg);
           checkFlag = true;
         }

//       if ((wherelower.indexOf("orderby") == -1) || (wherelower.indexOf("orderby") == -1 )) {
//           String msg = ms.getMessage("CMN0002", new String[] { "「ORDER BY」" }, null);
//           result.rejectValue("sqlWhereDef", "", msg);
//           checkFlag = true;
//       }

       if (mgpCsvExportService.systemIdCheck(form)) {
           String msg = ms.getMessage("CMN0005", new String[] { form.getSystemId()}, null);
           //result.rejectValue("systemId", "", msg);
           result.reject("", msg);
           checkFlag = true;
       }

       if (mgpCsvExportService.fileNameCheck(form)) {
    	   StringBuilder fileFullName  = new StringBuilder();
    	   fileFullName.append(form.getParentFilePath());
    	   String subFilePath = form.getSubFilePath();
   	       if(StringUtils.isNotBlank(subFilePath)){
  	    	    fileFullName.append(subFilePath);
   	    	    if(subFilePath.length()  != subFilePath.lastIndexOf("/")) {
     	    	    fileFullName.append("/");
   	         	}
   	       }
			switch(form.getFileNamingClass()){
			case "0":
		 	    fileFullName.append(form.getFileName());
			    break;
			case "1":
		 	    fileFullName.append("YYYYMMDD_");
		 	    fileFullName.append(form.getFileName());
			    break;
			case "2":
		 	    fileFullName.append("YYYYMMDDHHMMSS_");
   	       fileFullName.append(form.getFileName());
			    break;
			case "3":
		 	    fileFullName.append(form.getFileName());
		 	    fileFullName.append("_YYYYMMDD");
			    break;
			case "4":
		 	    fileFullName.append(form.getFileName());
		 	    fileFullName.append("_YYYYMMDDHHMMSS");
			    break;
		    }

   	       fileFullName.append(".");
   	       fileFullName.append(StringUtils.lowerCase(form.getFileClass()));

           String msg = ms.getMessage("CMN0006", new String[] { fileFullName.toString() }, null);
//         result.rejectValue("fileName", "", msg);
//         result.rejectValue("subFilePath", "", "");
//         result.rejectValue("fileClass", "", "");
           result.reject("", msg);

           checkFlag = true;
       }

       if (checkFlag) {
			LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "登録ボタン押下処理相関チェック", "異常終了");
           return OWN_PAGE;
       }

        try{
        	mgpCsvExportService.run(sql);
            mgpCsvExportService.saveData(form);
			form.setMgpCsvExportList(mgpCsvExportService.selectMgpCsvExportSearch());
			for(MgpCsvExportDefInfo mgpCsvExportDefInfo: form.getMgpCsvExportList()){
				if(mgpCsvExportDefInfo.getSystemId().equals(form.getSystemId())){
					form.setSqlNo(mgpCsvExportDefInfo.getSqlNo());
					form.setSelectClassCodeBak(mgpCsvExportDefInfo.getSqlNo().toString());
				}
			}
        }catch(Exception ex){
            //例外発生時の処理
           result.reject("", ex.getMessage()); // エラーメッセージ表示
			LogService.system("汎用CSV設定画面処理", "MgpCsvExportController", "登録ボタン押下処理", "失敗した");
			LogService.system(ExceptionUtils.getStackTrace(ex));
			LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "登録ボタン押下処理", "··異常終了");
           return OWN_PAGE;
       }

        //新しいアクセストークン設定
        saveAccessToken(form);

        // 完了メッセージ
        String msg = ms.getMessage("CMN0003", new String[] { "登録" }, null);
        model.addAttribute("axioMessage", msg);
        form.setSaveFlg("0");
    	form.setChangedDataSqlWhereDefFlg("");;
    	form.setChangedDataRedrawFlg("");
    	form.setChangedDataFlg("");
    	if ("1".equals(form.getEditFlg())) {
    		// 新規登録処理後の場合、画面を再表示したら、更新モードに切り替え
    		form.setEditFlg("2");
    		// バージョンは１に設定する
    		form.setVersionNumber(Integer.valueOf(1));
    	} else {
    		// その以外、更新後、バージョンを＋１
    		form.setVersionNumber(form.getVersionNumber() + 1);
    	}
		LogService.info("汎用CSV設定画面処理", "MgpCsvExportController", "登録ボタン押下処理", "正常終了");
    	return OWN_PAGE;
    }

	/**
	 * formの情報を初期化する。
	 *
	 * @param form
	 * @return form
	 */
	private MgpCsvExportForm resetFormSearch(MgpCsvExportForm form) {
		form.setSqlNo(null);
		form.setSelectClassCode("");
		form.setSelectClassCodeBak("");
		form.setSystemId("");
		form.setSqlRegisterName("");
		form.setValidFlag("1");
		form.setParentFilePath("");
		form.setSubFilePath("");
		form.setFileName("");
		form.setFileClass("csv");
		form.setFileNamingClass("1");
		form.setStrCode("1");
		form.setDelimiterClass("1");
		form.setFileCodeFormatClass("1");
		form.setSeparationDefClass("1");
		form.setFileHeaderInfoClass("1");
		form.setSqlOutTableName("");
		form.setSqlOutTableNameBak("");
		form.setSqlOutData("");
		form.setSqlColumnDef("");
		form.setSqlInputDataTxt("");
		form.setSqlWhereDef("");
		form.setEditFlg("1");
		form.setParentFilePath(parentFilePath);
		form.setChangedDataFlg("");
		form.setChangedDataRedrawFlg("");
		form.setChangedDataSqlWhereDefFlg("");
		form.setTargetViewInfoList(new ArrayList<TargetViewInfoResultListDto>());
		form.setTargetViewOutList(new ArrayList<TargetViewInfoResultListDto>());
		return form;
	}

    /**
     * 文字コード一覧取得
     * @throws UnsupportedEncodingException
     *
     */
    public List<CodeValueDto> strCodeListGet () throws UnsupportedEncodingException{
    	List<CodeValueDto> codeValueDtolist =  new ArrayList<>();
    	String[] codes = codeValue.split(",");
    	String[] names = codeName.split(",");
    	CodeValueDto codeValueDto =null;
    	for(int i =0;i< codes.length;i++) {
    		codeValueDto =new CodeValueDto();
    		codeValueDto.setCodeValue(codes[i]);
//			codeValueDto.setCodeName(new String( names[i].getBytes("ISO-8859-1" ),"UTF-8"));
			codeValueDto.setCodeName(new String( names[i].getBytes("UTF-8" ),"UTF-8"));

    		codeValueDtolist.add(codeValueDto);
    	}

    	return codeValueDtolist;
    }

    /**
           * 抽出元情報一覧編集
     * @throws UnsupportedEncodingException
     *
     */
    public List<TargetViewInfoResultListDto> targetView (String sqlOutData) {
    	List<TargetViewInfoResultListDto> targetViewlist =  new ArrayList<>();
    	if (StringUtils.isEmpty(sqlOutData)) {
        	return targetViewlist;
    	}
    	TargetViewInfoResultListDto targetViewInfo =null;
    	String[] tr = sqlOutData.split(";");
    	String[] td = null;
    	for(int i =0;i< tr.length;i++) {
    		targetViewInfo = new TargetViewInfoResultListDto();
            td = tr[i].split(",");
        	for(int j =0;j< td.length;j++) {
        		if (j==0) {
        			targetViewInfo.setDirNo(td[j]);
        		} else  if (j==1){
        			targetViewInfo.setColumnPhysicalName(td[j]);
        		} else {
        			targetViewInfo.setColumnLogicalName(td[j]);
        		}

        	}
			targetViewlist.add(targetViewInfo);
    	}
    	return targetViewlist;
    }

    /**
     * 抽出元参照項目一覧編集
	* @throws UnsupportedEncodingException
	*
	*/
    public String refTargetItemList(String colDefInfo) {
    	StringBuilder rf = new StringBuilder();
    	if(!StringUtils.isBlank(colDefInfo)) {
    		String[] sp = colDefInfo.split(";");
    		for (String cs : sp) {
    			if(!StringUtils.isBlank(cs)) {
    				String[] rs = cs.split(",");
    				if(rs != null && rs.length>2) {
    					rf.append(rs[0] + " " + rs[1] + " " + rs[2] + "<br>");
    				}
    			}
    		}
    	}

    	return rf.toString();
    }
}
