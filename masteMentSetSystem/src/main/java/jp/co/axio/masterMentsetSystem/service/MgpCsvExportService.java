package jp.co.axio.masterMentsetSystem.service;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jp.co.axio.masterMentsetSystem.common.LogService;
import jp.co.axio.masterMentsetSystem.controller.MgpCsvExportForm;
import jp.co.axio.masterMentsetSystem.dto.TargetViewInfoResultListDto;
import jp.co.axio.masterMentsetSystem.model.MgpCsvExportDefInfo;
import jp.co.axio.masterMentsetSystem.model.MgpCsvExportDefInfoExample;
import jp.co.axio.masterMentsetSystem.model.OutputScopeMst;
import jp.co.axio.masterMentsetSystem.model.OutputScopeMstExample;
import jp.co.axio.masterMentsetSystem.repository.MgpCsvExportDefInfoMapper;
import jp.co.axio.masterMentsetSystem.repository.OutputScopeMstMapper;
import jp.co.axio.masterMentsetSystem.repository.TargetViewMapper;

/**
 * 汎用CSV設定画面処理サービスクラス
 *
 * @author JCBC
 * @version 1.0
 */
@Service
public class MgpCsvExportService {

    @Autowired
    MgpCsvExportDefInfoMapper mgpCsvExportDefInfoMapper;

    @Autowired
    OutputScopeMstMapper outputScopeMstMapper;

    @Autowired
    TargetViewMapper targetViewMapper;

    // application.propertiesより取得
    @Value("${spring.datasource.url}")
    private String dbUrl;

    @Value("${spring.datasource.username}")
    private String dbUser;

    @Value("${spring.datasource.password}")
    private String dbPass;

    @Value("${spring.datasource.driver-class-name}")
    private String dbDriver;

    /**
     　　　* 汎用CSV出力定義情報からデータ取得 select
     * @return CSVファイル情報リストデータ
     */
    @Transactional
    public List<MgpCsvExportDefInfo> selectMgpCsvExportSearch () throws Exception{
        LogService.info("汎用CSV設定画面", "MgpCsvExportService", "分類コード名称リスト検索処理", "開始");
        MgpCsvExportDefInfoExample example = new MgpCsvExportDefInfoExample();
        example.setOrderByClause("sql_no");
		List<MgpCsvExportDefInfo> classCodeInfo = mgpCsvExportDefInfoMapper.selectByExample(example);
        LogService.info("汎用CSV設定画面", "MgpCsvExportService", "分類コード名称リスト検索処理", "正常終了");
    	return classCodeInfo;
    }

    /**
     　　　* 汎用CSV出力定義情報か選択したデータ取得 select
	 * @return CSVファイル情報選択したデータ
	 */
	@Transactional
	public MgpCsvExportDefInfo selectCsvFiledata (Integer sqlNo) throws Exception{
	    LogService.info("汎用CSV設定画面", "MgpCsvExportService", "CSVファイル情報に選択したデータ取得", "開始");
	    MgpCsvExportDefInfo mgpCsvExportDefInfo = mgpCsvExportDefInfoMapper.selectByPrimaryKey(sqlNo);
	    LogService.info("汎用CSV設定画面", "MgpCsvExportService", "CSVファイル情報に選択したデータ取得", "正常終了");
		return mgpCsvExportDefInfo;
	}


    /**
            *出力対象リスト取得 select
     * @param
     * @return 出力対象リスト
     */
    @Transactional
    public List<OutputScopeMst> selectMstExportSearch () throws Exception{
        LogService.info("汎用CSV設定画面", "MgpCsvExportService", "分類リスト検索処理", "開始");
        OutputScopeMstExample example = new OutputScopeMstExample();
    	List<OutputScopeMst> outputScopeMstList = outputScopeMstMapper.selectByExample(example);
        LogService.info("汎用CSV設定画面", "MgpCsvExportService", "分類リスト検索処理", "正常終了");
    	return outputScopeMstList;
    }

    /**
     * 抽出元情報一覧取得
     * @form
     */
    @Transactional
    public List<TargetViewInfoResultListDto> selectTargetViewInfoSearchResult (String viewName) throws Exception{
    	List<TargetViewInfoResultListDto> targetViewInfo = targetViewMapper.selectAllByView(viewName);

    	return targetViewInfo;
    }


    /**
    　　　* システム名存在チェック
     * @form
     */
    @Transactional
    public Boolean systemIdCheck (MgpCsvExportForm form) {
    	Boolean checkFlag=false;
    	MgpCsvExportDefInfo example = new MgpCsvExportDefInfo();
    	example.setSystemId(form.getSystemId());
    	example.setSqlNo(form.getSqlNo());
    	long count = targetViewMapper.countBySystemId(example);
    	if(count > 0) {
    		checkFlag=true;
    	}

    	return checkFlag;
    }


    /**
     * ファイル名存在チェック
     * @form
     */
    @Transactional
    public Boolean fileNameCheck (MgpCsvExportForm form) {
    	Boolean checkFlag=false;
    	MgpCsvExportDefInfo example = new MgpCsvExportDefInfo();
    	StringBuilder fileSavePath = new StringBuilder();
	    fileSavePath.append(form.getParentFilePath());
	    if(StringUtils.isNotBlank(form.getSubFilePath())){
		    fileSavePath.append(form.getSubFilePath());
	    }
	    example.setFileSavePath(fileSavePath.toString());

    	example.setFileName(form.getFileName());
    	example.setFileClass(form.getFileClass());
    	example.setFileNamingClass(form.getFileNamingClass());
    	example.setSqlNo(form.getSqlNo());
    	long count = targetViewMapper.countByFullFile(example);
    	if(count > 0) {
    		checkFlag=true;
    	}

    	return checkFlag;
    }

    /**
     * SQL実行できたか判定
     * @throws Exception
     * @parm SQL
     *
     */
    @Transactional
    public String run(String sql) throws Exception{

        LogService.info("汎用CSV設定画面", "MgpCsvExportService", "SQL実行処理", "開始");
        //変数定義
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        Integer cnt = 0;

            //JDBCドライバをロードする
            Class.forName(dbDriver);

            //DBへのコネクションを作成する
            conn = DriverManager.getConnection(dbUrl, dbUser, dbPass);

            //実行するSQL文とパラメータを指定する
            ps = conn.prepareStatement(sql, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
            //SELECTを実行する
            rs = ps.executeQuery();

            if (rs != null) {
            	rs.last();
            	cnt = rs.getRow();
            }

            //クローズ処理
            if(rs != null) rs.close();
            if(ps != null) ps.close();
            if(conn != null) conn.close();
            LogService.info("汎用CSV設定画面", "MgpCsvExportService", "SQL実行処理", "正常終了");
    	return cnt.toString();
    }

    /**
     *  汎用CSV出力定義情報登録・更新処理
     */
    @Transactional
    public void saveData(MgpCsvExportForm form) throws Exception{
        LogService.info("汎用CSV設定画面", "MgpCsvExportService", "汎用CSV出力定義情報登録・更新処理", "開始");
	    StringBuilder fileSavePath =null;
	    switch(form.getEditFlg()){
	    case "1":
		// 登録処理
		MgpCsvExportDefInfo insertEntity = new MgpCsvExportDefInfo();
		insertEntity.setSystemId(form.getSystemId());
		insertEntity.setSqlRegisterName(form.getSqlRegisterName());
		insertEntity.setValidFlag(form.getValidFlag());

	    fileSavePath = new StringBuilder();
	    fileSavePath.append(form.getParentFilePath());
	    if(StringUtils.isNotBlank(form.getSubFilePath())){
		    fileSavePath.append(form.getSubFilePath());
	    }
		insertEntity.setFileSavePath(fileSavePath.toString());

		insertEntity.setFileName(form.getFileName());
		insertEntity.setFileClass(form.getFileClass());
		insertEntity.setFileNamingClass(form.getFileNamingClass());
		insertEntity.setStrCode(form.getStrCode());
		insertEntity.setDelimiterClass(form.getDelimiterClass());
		insertEntity.setFileCodeFormatClass(form.getFileCodeFormatClass());
		insertEntity.setSeparationDefClass(form.getSeparationDefClass());
		insertEntity.setFileHeaderInfoClass(form.getFileHeaderInfoClass());
		insertEntity.setSqlOutTableName(form.getSqlOutTableName());
		insertEntity.setSqlOutData(form.getSqlOutData());
	    insertEntity.setSqlColumnDef(form.getSqlColumnDef());
	    insertEntity.setSqlWhereDef(form.getSqlWhereDef());

		insertEntity.setVersionNumber(new Integer("1"));
		mgpCsvExportDefInfoMapper.insertSelective(insertEntity);
		break;

	    case "2":
	    MgpCsvExportDefInfo updateEntity = new MgpCsvExportDefInfo();

	    updateEntity.setSqlNo(form.getSqlNo());
	    updateEntity.setSystemId(form.getSystemId());
	    updateEntity.setSqlRegisterName(form.getSqlRegisterName());
	    updateEntity.setValidFlag(form.getValidFlag());

	    fileSavePath = new StringBuilder();
	    fileSavePath.append(form.getParentFilePath());
	    if(StringUtils.isNotBlank(form.getSubFilePath())){
		    fileSavePath.append(form.getSubFilePath());
	    }
	    updateEntity.setFileSavePath(fileSavePath.toString());

	    updateEntity.setFileName(form.getFileName());
	    updateEntity.setFileClass(form.getFileClass());
	    updateEntity.setFileNamingClass(form.getFileNamingClass());
	    updateEntity.setStrCode(form.getStrCode());
	    updateEntity.setDelimiterClass(form.getDelimiterClass());
	    updateEntity.setFileCodeFormatClass(form.getFileCodeFormatClass());
	    updateEntity.setSeparationDefClass(form.getSeparationDefClass());
	    updateEntity.setFileHeaderInfoClass(form.getFileHeaderInfoClass());
	    updateEntity.setSqlOutTableName(form.getSqlOutTableName());
	    updateEntity.setSqlOutData(form.getSqlOutData());
	    updateEntity.setSqlColumnDef(form.getSqlColumnDef());
	    updateEntity.setSqlWhereDef(form.getSqlWhereDef());
		updateEntity.setVersionNumber(new Integer(form.getVersionNumber() + 1));

		mgpCsvExportDefInfoMapper.updateByPrimaryKeySelective(updateEntity);
		break;
	    }
        LogService.info("汎用CSV設定画面", "MgpCsvExportService", "汎用CSV出力定義情報登録・更新処理", "正常終了");
	    }

}
