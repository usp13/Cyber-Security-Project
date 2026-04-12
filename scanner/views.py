from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import CustomUserCreationForm, PasswordGeneratorForm, IPLookupForm, TextScanForm
from .models import UrlScan, IpScan, ContactMessage, TextScan, FileScan, PortScan, CommunityPost, CommunityComment
from .services import analyze_url, lookup_ip, generate_password as services_generate_password, analyze_phishing_text, check_email_breaches, scan_file_virus_total, perform_port_scan
import json
from PIL import Image
try:
    from pyzbar.pyzbar import decode
except ImportError:
    pass



@login_required
def home(request):
    return render(request, 'scanner/home.html')


@login_required
def scan_url(request):
    external_url = request.GET.get('q') or request.POST.get('url')
    if external_url:
        url = external_url.strip()
        if url:
            result = analyze_url(url)

            scan = UrlScan.objects.create(
                user=request.user if request.user.is_authenticated else None,
                url=url,
                normalized_url=result.get('normalized_url', ''),
                verdict=result.get('verdict', ''),
                score=result.get('risk_score', 0),
                report_json=json.dumps(result)
            )

            return render(request, 'scanner/result.html', {
                'report': result,
                'scan': scan,
            })

    return render(request, 'scanner/scan.html')


@login_required
def scan_result(request, scan_id):
    scan = get_object_or_404(UrlScan, id=scan_id)

    try:
        result = json.loads(scan.report_json)
    except Exception:
        result = {
            'normalized_url': scan.normalized_url,
            'verdict': scan.verdict,
            'score': scan.score,
            'reasons': [],
        }

    return render(request, 'scanner/result.html', {
        'scan': scan,
        'report': result,
    })


@login_required
def check_ip(request):
    result = None
    form = IPLookupForm()

    q = request.GET.get('q')
    if q or request.method == 'POST':
        if q:
            ip_address = q.strip()
        else:
            form = IPLookupForm(request.POST)
            if form.is_valid():
                ip_address = form.cleaned_data['ip_address']
            else:
                ip_address = None

        if ip_address:
            ip_info = lookup_ip(ip_address)
            IpScan.objects.create(
                user=request.user,
                ip_address=ip_address,
                version=ip_info.get('version', ''),
                reverse_dns=ip_info.get('reverse_dns', ''),
                is_private=ip_info.get('is_private', False)
            )
            result = json.dumps(ip_info, indent=2)

    return render(request, 'scanner/check_ip.html', {'result': result, 'form': form})

@login_required
def scan_text(request):
    result = None
    form = TextScanForm()

    q = request.GET.get('q')
    if q or request.method == 'POST':
        if q:
            text_content = q.strip()
        else:
            form = TextScanForm(request.POST)
            if form.is_valid():
                text_content = form.cleaned_data['text_content']
            else:
                text_content = None

        if text_content:
            result_data = analyze_phishing_text(text_content)
            TextScan.objects.create(
                user=request.user,
                text_content=text_content[:2000],
                verdict=result_data['verdict'],
                score=result_data['score'],
                reasons_json=json.dumps(result_data['reasons'])
            )
            result = result_data

    return render(request, 'scanner/text_scan.html', {'result': result, 'form': form})


@login_required
def check_qr(request):
    context = {}
    if request.method == 'POST':
        decoded_text = None
        
        if 'qr_text' in request.POST and request.POST['qr_text'].strip():
            decoded_text = request.POST['qr_text'].strip()
            
        elif request.FILES.get('qr_image'):
            try:
                image_file = request.FILES['qr_image']
                img = Image.open(image_file)
                try:
                    decoded_objects = decode(img)
                except NameError:
                    context['error'] = 'pyzbar library is not available. Please install it to decode QR codes.'
                    return render(request, 'scanner/qr.html', context)
                
                if decoded_objects:
                    decoded_text = decoded_objects[0].data.decode('utf-8')
                else:
                    context['error'] = 'No QR code found in the uploaded image.'
            except Exception as e:
                context['error'] = f'Error processing image: {str(e)}'

        if decoded_text:
            context['decoded_text'] = decoded_text
            
            if decoded_text.startswith('http://') or decoded_text.startswith('https://'):
                result = analyze_url(decoded_text)
                
                scan = UrlScan.objects.create(
                    user=request.user if request.user.is_authenticated else None,
                    url=decoded_text,
                    normalized_url=result.get('normalized_url', ''),
                    verdict=result.get('verdict', ''),
                    score=result.get('risk_score', 0),
                    report_json=json.dumps(result)
                )
                
                return render(request, 'scanner/result.html', {
                    'report': result,
                    'scan': scan,
                })
                
    return render(request, 'scanner/qr.html', context)


@login_required
def generate_password(request):
    if request.method == 'POST':
        form = PasswordGeneratorForm(request.POST)
        if form.is_valid():
            length = form.cleaned_data.get('length')
            include_symbols = form.cleaned_data.get('include_symbols')
            include_digits = form.cleaned_data.get('include_digits')
            include_uppercase = form.cleaned_data.get('include_uppercase')
            
            pwd = services_generate_password(
                length=length,
                include_symbols=include_symbols,
                include_digits=include_digits,
                include_uppercase=include_uppercase
            )
            return render(request, 'scanner/password.html', {'form': form, 'password': pwd})
    else:
        form = PasswordGeneratorForm()
    
    return render(request, 'scanner/password.html', {'form': form})


def contact(request):
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        email = request.POST.get('email', '').strip()
        subject = request.POST.get('subject', '').strip()
        message = request.POST.get('message', '').strip()
        if name and email and message:
            ContactMessage.objects.create(name=name, email=email, subject='Contact Form Submission', message=message)
            messages.success(request, 'Your message has been sent successfully!')
            return redirect('contact')
    return render(request, 'scanner/contact.html')


def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('home')
    else:
        form = CustomUserCreationForm()
    return render(request, 'scanner/register.html', {'form': form})


@login_required
def history(request):
    url_scans = list(UrlScan.objects.filter(user=request.user))
    ip_scans = list(IpScan.objects.filter(user=request.user))
    text_scans = list(TextScan.objects.filter(user=request.user))
    file_scans = list(FileScan.objects.filter(user=request.user))
    port_scans = list(PortScan.objects.filter(user=request.user))
    all_scans = url_scans + ip_scans + text_scans + file_scans + port_scans
    all_scans.sort(key=lambda x: x.created_at, reverse=True)
    return render(request, 'scanner/history.html', {'scans': all_scans})

@login_required
def check_breach(request):
    result = None
    email_queried = None
    
    if request.method == 'POST':
        email_queried = request.POST.get('email', '').strip()
        if email_queried:
            result = check_email_breaches(email_queried)
            
    return render(request, 'scanner/breach_check.html', {
        'result': result,
        'email_queried': email_queried
    })

@login_required
def scan_file(request):
    result = None
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        result = scan_file_virus_total(uploaded_file)
        
        if result['scanned']:
            FileScan.objects.create(
                user=request.user,
                file_name=result['file_name'],
                file_hash=result['hash'],
                verdict='Infected' if result['malicious'] else 'Clean',
                score=result['detections'],
                total_engines=result['total_engines'],
                report_json=json.dumps(result.get('report_data', {}))
            )

    return render(request, 'scanner/file_scan.html', {'result': result})

@login_required
def network_recon(request):
    result = None
    if request.method == 'POST':
        target = request.POST.get('target', '').strip()
        if target:
            result = perform_port_scan(target)
            if not result.get('error'):
                PortScan.objects.create(
                    user=request.user,
                    target=result['target'],
                    ip_address=result['ip'],
                    open_ports_json=json.dumps(result['open_ports'])
                )
    return render(request, 'scanner/recon.html', {'result': result})


@login_required
def community_list(request):
    scam_type = request.GET.get('type', '')
    posts = CommunityPost.objects.all()
    if scam_type:
        posts = posts.filter(scam_type=scam_type)
    return render(request, 'scanner/community_list.html', {
        'posts': posts,
        'scam_type': scam_type,
        'scam_choices': CommunityPost.SCAM_TYPE_CHOICES,
    })


@login_required
def community_create(request):
    if request.method == 'POST':
        title = request.POST.get('title', '').strip()
        scam_type = request.POST.get('scam_type', 'other')
        scam_source = request.POST.get('scam_source', '').strip()
        description = request.POST.get('description', '').strip()
        is_anonymous = request.POST.get('is_anonymous') == 'on'

        if title and description:
            CommunityPost.objects.create(
                user=request.user,
                title=title,
                scam_type=scam_type,
                scam_source=scam_source,
                description=description,
                is_anonymous=is_anonymous,
            )
            messages.success(request, 'Your experience has been shared with the community.')
            return redirect('community_list')
        else:
            messages.error(request, 'Please fill in the title and description.')

    return render(request, 'scanner/community_create.html', {
        'scam_choices': CommunityPost.SCAM_TYPE_CHOICES,
    })


@login_required
def community_detail(request, post_id):
    post = get_object_or_404(CommunityPost, id=post_id)

    if request.method == 'POST':
        content = request.POST.get('content', '').strip()
        is_anonymous = request.POST.get('is_anonymous') == 'on'
        if content:
            CommunityComment.objects.create(
                post=post,
                user=request.user,
                content=content,
                is_anonymous=is_anonymous,
            )
            messages.success(request, 'Your reply has been posted.')
            return redirect('community_detail', post_id=post.id)

    comments = post.comments.all()
    return render(request, 'scanner/community_detail.html', {
        'post': post,
        'comments': comments,
    })