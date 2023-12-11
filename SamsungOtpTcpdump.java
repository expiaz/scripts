import java.text.DecimalFormat;
import java.util.Calendar;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.Date;
import java.text.ParseException;

class Otp {

    public static String GetDateString(Calendar calendar) {
        StringBuilder sb = new StringBuilder(String.valueOf(String.valueOf(new DecimalFormat("00").format(calendar.get(1) - 2000)) + new DecimalFormat("00").format(calendar.get(2) + 1)));
        sb.append(new DecimalFormat("00").format((long) calendar.get(12)));
        return String.valueOf(String.valueOf(sb.toString()) + new DecimalFormat("00").format(calendar.get(5))) + new DecimalFormat("00").format((long) calendar.get(11));
    }

    public static String fromNow(int i) throws ParseException {
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        calendar.add(12, i * (-1));
        System.out.println(new SimpleDateFormat("dd-M-yyyy hh:mm:ss Z").format(calendar.getTime()));
        return GetDateString(calendar);
    }

    public static String fromDate(String strDate, int i) throws ParseException {
        SimpleDateFormat sdf = new SimpleDateFormat("dd-M-yyyy hh:mm:ss Z");
        Date date = sdf.parse(strDate);
        System.out.println(date);
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        calendar.setTime(date);
        calendar.add(12, i * (-1));
        System.out.println(new SimpleDateFormat("dd-M-yyyy hh:mm:ss Z").format(calendar.getTime()));
        return GetDateString(calendar);
    }

    public static int MakeHashCode(String str) {
        int i = 0;
        for (int i2 = 0; i2 < str.length(); i2++) {
            i = str.charAt(i2) + (i << 5) + i;
        }
        return i < 0 ? i * (-1) : i;
    }

    public static void main(String[] args) {
        try {
            for (int i=4; i >= 0 ; i--) {
                System.out.println(Integer.toString(MakeHashCode(String.valueOf(args[0]) + (args.length > 1 ? fromDate(args[1], i) : fromNow(i)))));
            }
        } catch (ParseException ex) {
            System.out.println(ex);
        }
    }
}