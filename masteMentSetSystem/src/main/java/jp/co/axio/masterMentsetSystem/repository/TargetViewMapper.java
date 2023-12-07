package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import jp.co.axio.masterMentsetSystem.dto.TargetViewInfoResultListDto;
import jp.co.axio.masterMentsetSystem.model.MgpCsvExportDefInfo;

@Mapper
public interface TargetViewMapper {

    List<TargetViewInfoResultListDto> selectAllByView(@Param("sqlOutTableName") String sqlOutTableName);
    
    long countBySystemId(MgpCsvExportDefInfo record);
    
    long countByFullFile(MgpCsvExportDefInfo record);
}