package telran.ashkelon2020.forum.dto;

import java.time.LocalDate;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class DatePeriodDto {
	LocalDate dateFrom;
	LocalDate dateTo;
}
