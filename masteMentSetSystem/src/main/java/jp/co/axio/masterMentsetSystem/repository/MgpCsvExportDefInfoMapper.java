package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;
import jp.co.axio.masterMentsetSystem.model.MgpCsvExportDefInfo;
import jp.co.axio.masterMentsetSystem.model.MgpCsvExportDefInfoExample;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

@Mapper
public interface MgpCsvExportDefInfoMapper {
    long countByExample(MgpCsvExportDefInfoExample example);

    int deleteByExample(MgpCsvExportDefInfoExample example);

    int deleteByPrimaryKey(Integer sqlNo);

    int insert(MgpCsvExportDefInfo record);

    int insertSelective(MgpCsvExportDefInfo record);

    List<MgpCsvExportDefInfo> selectByExample(MgpCsvExportDefInfoExample example);

    MgpCsvExportDefInfo selectByPrimaryKey(Integer sqlNo);

    int updateByExampleSelective(@Param("record") MgpCsvExportDefInfo record, @Param("example") MgpCsvExportDefInfoExample example);

    int updateByExample(@Param("record") MgpCsvExportDefInfo record, @Param("example") MgpCsvExportDefInfoExample example);

    int updateByPrimaryKeySelective(MgpCsvExportDefInfo record);

    int updateByPrimaryKey(MgpCsvExportDefInfo record);
}