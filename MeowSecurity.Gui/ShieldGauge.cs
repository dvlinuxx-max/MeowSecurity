using System;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace MeowSecurity.Gui;

/// <summary>
/// The signature instrument: a radial protection gauge with a slow radar sweep.
///
/// It draws a 280° track with a value arc proportional to <see cref="Score"/>,
/// a glowing tip where the arc ends, faint tick marks for an instrument feel,
/// and a continuously rotating sweep line — the one bold, moving thing in the app.
/// The score number and label are overlaid as text by the host, so this control
/// stays purely the dial.
/// </summary>
public sealed class ShieldGauge : FrameworkElement
{
    private const double GapDeg = 80;                 // opening at the bottom
    private const double StartDeg = 180 + GapDeg / 2; // first drawn angle (lower-left)
    private const double SweepDeg = 360 - GapDeg;     // total travel of the track

    public ShieldGauge()
    {
        // The radar sweep: one orchestrated, always-on motion. Everything else is still.
        //
        // "Always-on" is the expensive word. SweepAngle affects rendering, so this animation
        // called OnRender at the compositor's full frame rate, forever — and OnRender rebuilt
        // two arc geometries, twenty-nine tick marks, four pens and a gradient brush every
        // time. Measured, the window being visible cost twenty-two per cent of a processor
        // core while the monitoring behind it cost four: almost the entire running cost of
        // this program was one ornament redrawing itself sixty times a second.
        //
        // Twenty frames a second is still perfectly smooth for a line that takes four seconds
        // to go round once, and the dial behind it is now drawn once and reused, so a frame
        // costs one line and a dot instead of the whole instrument.
        Loaded += (_, _) => Animate(true);
    }

    private static readonly DoubleAnimation Spin = CreateSpin();

    private static DoubleAnimation CreateSpin()
    {
        var spin = new DoubleAnimation(0, 360, new Duration(TimeSpan.FromSeconds(4)))
        {
            RepeatBehavior = RepeatBehavior.Forever,
        };
        Timeline.SetDesiredFrameRate(spin, 12);
        spin.Freeze();
        return spin;
    }

    /// <summary>
    /// Starts or stops the sweep.
    ///
    /// The sweep is there to reassure the person looking at the screen that the monitor is
    /// awake. Nobody is looking at a window that is not in front of them, and any continuous
    /// animation keeps the whole rendering pipeline running whether or not it is being seen —
    /// which for a program meant to sit in the background all day is a laptop battery spent on
    /// an ornament in a window nobody has open.
    /// </summary>
    public void Animate(bool on) =>
        BeginAnimation(SweepAngleProperty, on ? Spin : null);

    /// <summary>
    /// The dial without the sweep: track, ticks, value arc and tip. It depends only on the
    /// score, the colours and the size, none of which change from one frame to the next, so it
    /// is drawn into a cached drawing and replayed until one of them does.
    /// </summary>
    private Drawing? _dial;
    private double _dialScore = double.NaN, _dialWidth, _dialHeight;
    private Brush? _dialAccent, _dialTrack;

    private static void InvalidateDial(DependencyObject d, DependencyPropertyChangedEventArgs e) =>
        ((ShieldGauge)d)._dial = null;

    public static readonly DependencyProperty ScoreProperty = DependencyProperty.Register(
        nameof(Score), typeof(double), typeof(ShieldGauge),
        new FrameworkPropertyMetadata(100.0, FrameworkPropertyMetadataOptions.AffectsRender, InvalidateDial));

    public static readonly DependencyProperty AccentProperty = DependencyProperty.Register(
        nameof(Accent), typeof(Brush), typeof(ShieldGauge),
        new FrameworkPropertyMetadata(Brushes.Orange, FrameworkPropertyMetadataOptions.AffectsRender, InvalidateDial));

    public static readonly DependencyProperty TrackProperty = DependencyProperty.Register(
        nameof(Track), typeof(Brush), typeof(ShieldGauge),
        new FrameworkPropertyMetadata(Brushes.Gray, FrameworkPropertyMetadataOptions.AffectsRender, InvalidateDial));

    public static readonly DependencyProperty SweepAngleProperty = DependencyProperty.Register(
        nameof(SweepAngle), typeof(double), typeof(ShieldGauge),
        new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

    public double Score { get => (double)GetValue(ScoreProperty); set => SetValue(ScoreProperty, value); }
    public Brush Accent { get => (Brush)GetValue(AccentProperty); set => SetValue(AccentProperty, value); }
    public Brush Track { get => (Brush)GetValue(TrackProperty); set => SetValue(TrackProperty, value); }
    public double SweepAngle { get => (double)GetValue(SweepAngleProperty); set => SetValue(SweepAngleProperty, value); }

    protected override void OnRender(DrawingContext dc)
    {
        double size = Math.Min(ActualWidth, ActualHeight);
        if (size <= 0) return;

        var center = new Point(ActualWidth / 2, ActualHeight / 2);
        double r = size / 2 - 14;
        double thickness = Math.Max(7, size * 0.055);

        var accent = Accent ?? Brushes.Orange;
        var track = Track ?? Brushes.Gray;

        if (_dial is null || _dialScore != Score || _dialAccent != accent || _dialTrack != track ||
            _dialWidth != ActualWidth || _dialHeight != ActualHeight)
        {
            _dial = BuildDial(center, r, thickness, accent, track, Score);
            _dialScore = Score;
            _dialAccent = accent;
            _dialTrack = track;
            _dialWidth = ActualWidth;
            _dialHeight = ActualHeight;
        }

        dc.DrawDrawing(_dial);

        // Radar sweep — a rotating line that fades from centre to a bright edge. The only part
        // that genuinely differs from one frame to the next, and now the only part drawn per frame.
        double innerR = r - thickness - 6;
        if (innerR > 6)
        {
            var edge = PointAt(center, innerR, SweepAngle);
            var sweepBrush = new LinearGradientBrush
            {
                StartPoint = new Point(0.5, 0.5),
                EndPoint = RelativeEnd(SweepAngle),
                GradientStops =
                {
                    new GradientStop(Color.FromArgb(0, 255, 154, 56), 0.0),
                    new GradientStop(Color.FromArgb(90, 255, 154, 56), 0.75),
                    new GradientStop(Color.FromArgb(220, 255, 200, 120), 1.0),
                },
            };
            sweepBrush.Freeze();
            dc.DrawLine(new Pen(sweepBrush, 2.2), center, edge);

            var dot = accent.Clone();
            dot.Opacity = 0.9;
            dot.Freeze();
            dc.DrawEllipse(dot, null, edge, 2.6, 2.6);
        }
    }

    private static Drawing BuildDial(
        Point center, double r, double thickness, Brush accent, Brush track, double score)
    {
        var group = new DrawingGroup();
        using var dc = group.Open();

        // 1) Track — the full dial the value rides on.
        dc.DrawGeometry(null, new Pen(track, thickness) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round },
            Arc(center, r, StartDeg, SweepDeg));

        // 2) Tick marks around the dial — subtle, instrument-like.
        var tickPen = new Pen(track, 1.5);
        for (int i = 0; i <= 28; i++)
        {
            double a = StartDeg + SweepDeg * (i / 28.0);
            var p1 = PointAt(center, r + thickness / 2 + 4, a);
            var p2 = PointAt(center, r + thickness / 2 + (i % 7 == 0 ? 11 : 7), a);
            dc.DrawLine(tickPen, p1, p2);
        }

        double frac = Math.Clamp(score, 0, 100) / 100.0;
        double valueSweep = SweepDeg * frac;

        // 3) Glow bed behind the value arc — a fat, faint accent pass reads as a halo.
        if (valueSweep > 0.5)
        {
            var glow = accent.Clone();
            glow.Opacity = 0.22;
            dc.DrawGeometry(null, new Pen(glow, thickness + 12) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round },
                Arc(center, r, StartDeg, valueSweep));

            // 4) The value arc itself.
            dc.DrawGeometry(null, new Pen(accent, thickness) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round },
                Arc(center, r, StartDeg, valueSweep));

            // 5) Glowing tip where the value ends.
            var tip = PointAt(center, r, StartDeg + valueSweep);
            var halo = accent.Clone(); halo.Opacity = 0.35;
            dc.DrawEllipse(halo, null, tip, thickness, thickness);
            dc.DrawEllipse(accent, null, tip, thickness * 0.55, thickness * 0.55);
            dc.DrawEllipse(Brushes.White, null, tip, thickness * 0.2, thickness * 0.2);
        }

        dc.Close();
        group.Freeze();
        return group;
    }

    // Endpoint (in 0..1 element space) for the sweep gradient, so it brightens toward the line's tip.
    private static Point RelativeEnd(double angleDeg)
    {
        double rad = angleDeg * Math.PI / 180;
        return new Point(0.5 + 0.5 * Math.Sin(rad), 0.5 - 0.5 * Math.Cos(rad));
    }

    private static Point PointAt(Point c, double radius, double angleDeg)
    {
        double rad = angleDeg * Math.PI / 180;
        return new Point(c.X + radius * Math.Sin(rad), c.Y - radius * Math.Cos(rad));
    }

    private static Geometry Arc(Point c, double radius, double startDeg, double sweepDeg)
    {
        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            var start = PointAt(c, radius, startDeg);
            var end = PointAt(c, radius, startDeg + sweepDeg);
            ctx.BeginFigure(start, isFilled: false, isClosed: false);
            ctx.ArcTo(end, new Size(radius, radius), 0,
                isLargeArc: sweepDeg > 180, SweepDirection.Clockwise, isStroked: true, isSmoothJoin: false);
        }
        geo.Freeze();
        return geo;
    }
}
